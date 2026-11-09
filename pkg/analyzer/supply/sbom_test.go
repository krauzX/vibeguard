package supply

import (
	"regexp"
	"testing"
)

func TestBuildSBOM(t *testing.T) {
	root := t.TempDir()
	write(t, root, "go.mod", "module example.com/app\n\ngo 1.22\n\nrequire github.com/spf13/cobra v1.10.2\n")
	write(t, root, "package.json", `{"dependencies": {"lodash": "4.17.20"}}`)

	sbom := BuildSBOM(root, "9.9.9", false)

	if sbom.SpecVersion != "1.5" || sbom.BOMFormat != "CycloneDX" {
		t.Errorf("unexpected format %s %s", sbom.BOMFormat, sbom.SpecVersion)
	}
	if !regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(sbom.SerialNumber) {
		t.Errorf("serial number is not a v4 uuid: %s", sbom.SerialNumber)
	}
	if sbom.Metadata.Tools[0].Version != "9.9.9" {
		t.Errorf("tool version not reported: %+v", sbom.Metadata.Tools[0])
	}
	if len(sbom.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(sbom.Components))
	}

	first := sbom.Components[0]
	if first.PURL != "pkg:golang/github.com/spf13/cobra@1.10.2" || first.BOMRef != first.PURL {
		t.Errorf("unexpected golang component %+v", first)
	}
	if sbom.Components[1].PURL != "pkg:npm/lodash@4.17.20" {
		t.Errorf("unexpected npm component %+v", sbom.Components[1])
	}
}

func TestSBOMSerialIsFresh(t *testing.T) {
	if NewSBOM("1").SerialNumber == NewSBOM("1").SerialNumber {
		t.Error("two documents shared a serial number")
	}
}

func TestSBOMReproducibleRun(t *testing.T) {
	root := t.TempDir()
	write(t, root, "requirements.txt", "requests==2.31.0\n")

	first, err := BuildSBOM(root, "1.0.0", true).ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildSBOM(root, "1.0.0", true).ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("reproducible documents differ between runs")
	}

	sbom := BuildSBOM(root, "1.0.0", true)
	if sbom.Metadata.Timestamp != "" {
		t.Errorf("reproducible document kept a timestamp: %q", sbom.Metadata.Timestamp)
	}
	if !regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(sbom.SerialNumber) {
		t.Errorf("serial number is not a v4 shaped uuid: %s", sbom.SerialNumber)
	}
}

func TestSBOMJSON(t *testing.T) {
	root := t.TempDir()
	write(t, root, "requirements.txt", "requests==2.31.0\n")

	data, err := BuildSBOM(root, "1.0.0", true).ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || data[0] != '{' {
		t.Errorf("expected a json document, got %q", string(data[:min(20, len(data))]))
	}
}
