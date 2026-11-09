package supply

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const detailWorkers = 8

// Vuln is the slice of an OSV record that belongs in a finding.
type Vuln struct {
	ID      string   `json:"id"`
	Summary string   `json:"summary"`
	Fixed   string   `json:"fixed,omitempty"`
	Aliases []string `json:"aliases,omitempty"`
}

// Client talks to the OSV database and keeps a small on-disk cache.
type Client struct {
	HTTP    *http.Client
	BaseURL string
	Cache   string
	TTL     time.Duration
}

func NewClient() *Client {
	cache := ""
	if dir, err := os.UserCacheDir(); err == nil {
		cache = filepath.Join(dir, "vibeguard", "osv.json")
	}

	return &Client{
		HTTP:    &http.Client{Timeout: 20 * time.Second},
		BaseURL: "https://api.osv.dev",
		Cache:   cache,
		TTL:     24 * time.Hour,
	}
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

type osvRecord struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// Lookup returns advisories per dependency index within the context budget.
func (c *Client) Lookup(ctx context.Context, deps []Dependency) (map[int][]Vuln, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	byID := make(map[int][]string, len(deps))
	var ids []string
	seenID := make(map[string]bool)

	for start := 0; start < len(deps); start += 500 {
		end := min(start+500, len(deps))
		queries := make([]osvQuery, 0, end-start)
		for _, dep := range deps[start:end] {
			var q osvQuery
			q.Package.Name = dep.Name
			q.Package.Ecosystem = dep.Ecosystem
			q.Version = dep.Version
			queries = append(queries, q)
		}

		var resp osvBatchResponse
		if err := c.post(ctx, "/v1/querybatch", map[string]any{"queries": queries}, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != end-start {
			return nil, fmt.Errorf("osv returned %d results for %d queries", len(resp.Results), end-start)
		}

		for i, result := range resp.Results {
			for _, v := range result.Vulns {
				byID[start+i] = append(byID[start+i], v.ID)
				if !seenID[v.ID] {
					seenID[v.ID] = true
					ids = append(ids, v.ID)
				}
			}
		}
	}

	if len(ids) == 0 {
		return nil, nil
	}

	records, missing := c.details(ctx, ids)

	out := make(map[int][]Vuln, len(byID))
	for idx, vulnIDs := range byID {
		for _, id := range vulnIDs {
			record, ok := records[id]
			if !ok {
				record = Vuln{ID: id}
			}
			out[idx] = append(out[idx], record)
		}
	}

	if len(missing) > 0 {
		return out, fmt.Errorf("%d advisory detail(s) unavailable", len(missing))
	}

	return out, nil
}

func (c *Client) post(ctx context.Context, path string, body any, target any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv %s returned %s", path, resp.Status)
	}

	return json.NewDecoder(resp.Body).Decode(target)
}

// details resolves ids concurrently and falls back to stale cache entries.
func (c *Client) details(ctx context.Context, ids []string) (map[string]Vuln, []string) {
	cache := c.loadCache()
	out := make(map[string]Vuln, len(ids))
	now := time.Now()

	var pending []string
	for _, id := range ids {
		if entry, ok := cache.Entries[id]; ok && now.Before(entry.Expires) {
			out[id] = entry.Vuln
			continue
		}
		pending = append(pending, id)
	}

	fetched, failures := c.fetchAll(ctx, pending)
	for id, record := range fetched {
		out[id] = record
		cache.Entries[id] = cacheEntry{Expires: now.Add(c.TTL), Vuln: record}
	}

	var missing []string
	for _, id := range failures {
		if entry, ok := cache.Entries[id]; ok {
			out[id] = entry.Vuln
			continue
		}
		missing = append(missing, id)
	}

	c.saveCache(cache)

	return out, missing
}

type fetchResult struct {
	id   string
	vuln Vuln
	err  error
}

func (c *Client) fetchAll(ctx context.Context, ids []string) (map[string]Vuln, []string) {
	if len(ids) == 0 {
		return nil, nil
	}

	workers := min(detailWorkers, len(ids))
	results := make([]fetchResult, len(ids))
	queue := make(chan int)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range queue {
				vuln, err := c.fetch(ctx, ids[i])
				results[i] = fetchResult{id: ids[i], vuln: vuln, err: err}
			}
		}()
	}

	for i := range ids {
		queue <- i
	}
	close(queue)
	wg.Wait()

	out := make(map[string]Vuln, len(ids))
	var failures []string
	for _, result := range results {
		if result.err != nil {
			failures = append(failures, result.id)
			continue
		}
		out[result.id] = result.vuln
	}

	return out, failures
}

func (c *Client) fetch(ctx context.Context, id string) (Vuln, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return Vuln{}, err
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Vuln{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Vuln{}, fmt.Errorf("osv vulns/%s returned %s", id, resp.Status)
	}

	var record osvRecord
	if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
		return Vuln{}, err
	}

	vuln := Vuln{ID: record.ID, Summary: record.Summary, Aliases: record.Aliases}
	for _, affected := range record.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					vuln.Fixed = event.Fixed
					break
				}
			}
			if vuln.Fixed != "" {
				break
			}
		}
		if vuln.Fixed != "" {
			break
		}
	}

	return vuln, nil
}

type cacheEntry struct {
	Expires time.Time `json:"expires"`
	Vuln    Vuln      `json:"vuln"`
}

type cacheFile struct {
	Entries map[string]cacheEntry `json:"entries"`
}

func (c *Client) loadCache() cacheFile {
	file := cacheFile{Entries: map[string]cacheEntry{}}
	if c.Cache == "" {
		return file
	}

	data, err := os.ReadFile(c.Cache)
	if err != nil {
		return file
	}
	if err := json.Unmarshal(data, &file); err != nil || file.Entries == nil {
		return cacheFile{Entries: map[string]cacheEntry{}}
	}

	return file
}

func (c *Client) saveCache(file cacheFile) {
	if c.Cache == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.Cache), 0o755); err != nil {
		return
	}

	ids := make([]string, 0, len(file.Entries))
	for id := range file.Entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	data, err := json.Marshal(file)
	if err != nil {
		return
	}
	os.WriteFile(c.Cache, data, 0o644)
}
