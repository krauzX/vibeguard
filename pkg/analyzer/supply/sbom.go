package supply

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// SBOM is a CycloneDX 1.5 bill of materials built from the manifests on disk.
type SBOM struct {
	BOMFormat    string      `json:"bomFormat"`
	SpecVersion  string      `json:"specVersion"`
	SerialNumber string      `json:"serialNumber"`
	Version      int         `json:"version"`
	Metadata     Metadata    `json:"metadata"`
	Components   []Component `json:"components"`
}

type Metadata struct {
	Timestamp string `json:"timestamp,omitempty"`
	Tools     []Tool `json:"tools"`
}

type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Component struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// NewSBOM starts a document stamped with the tool version that produced it.
func NewSBOM(toolVersion string) *SBOM {
	return &SBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + newUUID(),
		Version:      1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []Tool{{
				Vendor:  "VibeGuard",
				Name:    "vibeguard",
				Version: toolVersion,
			}},
		},
		Components: []Component{},
	}
}

// Add appends one dependency with its package URL.
func (s *SBOM) Add(dep Dependency) {
	purl := purlFor(dep)
	s.Components = append(s.Components, Component{
		Type:    "library",
		BOMRef:  purl,
		Name:    dep.Name,
		Version: dep.Version,
		PURL:    purl,
	})
}

// BuildSBOM reads every manifest below root into a sorted component list. A
// reproducible document derives its serial from the components and drops the
// timestamp, so two runs over an unchanged tree are byte-identical.
func BuildSBOM(root, toolVersion string, reproducible bool) *SBOM {
	sbom := NewSBOM(toolVersion)
	if reproducible {
		sbom.SerialNumber = ""
		sbom.Metadata.Timestamp = ""
	}

	deps := ParseManifests(root)
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Ecosystem != deps[j].Ecosystem {
			return deps[i].Ecosystem < deps[j].Ecosystem
		}
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})

	for _, dep := range deps {
		sbom.Add(dep)
	}

	if reproducible {
		sbom.SerialNumber = "urn:uuid:" + serialFor(sbom)
	}

	return sbom
}

func (s *SBOM) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

func purlFor(dep Dependency) string {
	switch dep.Ecosystem {
	case "Go":
		return fmt.Sprintf("pkg:golang/%s@%s", dep.Name, dep.Version)
	case "npm":
		return fmt.Sprintf("pkg:npm/%s@%s", dep.Name, dep.Version)
	case "PyPI":
		return fmt.Sprintf("pkg:pypi/%s@%s", dep.Name, dep.Version)
	}
	return fmt.Sprintf("pkg:generic/%s@%s", dep.Name, dep.Version)
}

// serialFor hashes the components into a stable RFC 4122 version 4 shaped id.
func serialFor(s *SBOM) string {
	sum := sha256.New()
	sum.Write([]byte(s.Metadata.Tools[0].Name))
	sum.Write([]byte(s.Metadata.Tools[0].Version))
	for _, c := range s.Components {
		sum.Write([]byte(c.PURL))
		sum.Write([]byte{0})
	}

	b := sum.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// newUUID returns a random RFC 4122 version 4 identifier.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("00000000-0000-4000-8000-%012d", time.Now().UnixNano()%1e12)
	}

	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
