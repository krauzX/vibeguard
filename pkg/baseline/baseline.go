package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"
)

// ErrInvalidID rejects anything that is not a finding id from a report.
var ErrInvalidID = errors.New("baseline entries need a 16 character finding id")

var idPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

type SuppressedFinding struct {
	ID           string    `json:"id"`
	Reason       string    `json:"reason"`
	SuppressedAt time.Time `json:"suppressed_at"`
}

type Baseline struct {
	mu           sync.RWMutex
	filePath     string
	suppressions []SuppressedFinding
	byID         map[string]int
}

func New(filePath string) *Baseline {
	return &Baseline{
		filePath: filePath,
		byID:     make(map[string]int),
	}
}

func (b *Baseline) Load() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	data, err := os.ReadFile(b.filePath)
	if os.IsNotExist(err) {
		b.suppressions = nil
		b.reindex()
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read baseline file: %w", err)
	}

	var findings []SuppressedFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		return fmt.Errorf("failed to parse baseline file: %w", err)
	}

	b.suppressions = findings
	b.reindex()
	return nil
}

func (b *Baseline) Save() error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	data, err := json.MarshalIndent(b.suppressions, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal suppressions: %w", err)
	}

	if err := os.WriteFile(b.filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write baseline file: %w", err)
	}

	return nil
}

// Add is idempotent: accepting the same finding twice keeps one entry.
func (b *Baseline) Add(entry SuppressedFinding) error {
	if !idPattern.MatchString(entry.ID) {
		return fmt.Errorf("%w: %q", ErrInvalidID, entry.ID)
	}

	b.mu.Lock()
	if _, exists := b.byID[entry.ID]; exists {
		b.mu.Unlock()
		return nil
	}

	entry.SuppressedAt = time.Now().UTC()
	b.suppressions = append(b.suppressions, entry)
	b.reindex()
	b.mu.Unlock()

	return b.Save()
}

func (b *Baseline) IsSuppressed(id string) bool {
	if id == "" {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	_, exists := b.byID[id]
	return exists
}

func (b *Baseline) Suppressions() []SuppressedFinding {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]SuppressedFinding, len(b.suppressions))
	copy(result, b.suppressions)
	return result
}

func (b *Baseline) Remove(id string) (bool, error) {
	b.mu.Lock()
	position, exists := b.byID[id]
	if !exists {
		b.mu.Unlock()
		return false, nil
	}

	b.suppressions = append(b.suppressions[:position], b.suppressions[position+1:]...)
	b.reindex()
	b.mu.Unlock()

	return true, b.Save()
}

func (b *Baseline) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return len(b.suppressions)
}

func (b *Baseline) reindex() {
	b.byID = make(map[string]int, len(b.suppressions))
	for i := range b.suppressions {
		b.byID[b.suppressions[i].ID] = i
	}
}
