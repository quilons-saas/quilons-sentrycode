package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anchore/grype/grype/db/v6"
	grypeVersion "github.com/anchore/grype/grype/version"
	"github.com/anchore/packageurl-go"
)

const (
	scannerName     = "quilons-controlled-grype"
	scannerVersion  = "0.120.0-quilons.1"
	upstreamName    = "grype"
	upstreamVersion = "0.120.0"
)

type cycloneDXDocument struct {
	BOMFormat   string               `json:"bomFormat"`
	SpecVersion string               `json:"specVersion"`
	Components  []cycloneDXComponent `json:"components"`
}

type cycloneDXComponent struct {
	Type    string `json:"type,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type grypeDocument struct {
	Descriptor descriptor   `json:"descriptor"`
	Matches    []grypeMatch `json:"matches"`
	Source     sourceInfo   `json:"source"`
}

type descriptor struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Configuration any    `json:"configuration,omitempty"`
}

type sourceInfo struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

type grypeMatch struct {
	Vulnerability          grypeVulnerability     `json:"vulnerability"`
	RelatedVulnerabilities []relatedVulnerability `json:"relatedVulnerabilities,omitempty"`
	Artifact               grypeArtifact          `json:"artifact"`
	MatchDetails           []matchDetail          `json:"matchDetails,omitempty"`
}

type grypeVulnerability struct {
	ID          string  `json:"id"`
	DataSource  string  `json:"dataSource,omitempty"`
	Namespace   string  `json:"namespace,omitempty"`
	Severity    string  `json:"severity"`
	Description string  `json:"description,omitempty"`
	Fix         fixInfo `json:"fix"`
}

type fixInfo struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type relatedVulnerability struct {
	ID string `json:"id"`
}

type grypeArtifact struct {
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	PURL      string     `json:"purl"`
	Type      string     `json:"type,omitempty"`
	Locations []location `json:"locations"`
}

type location struct {
	Path string `json:"path"`
}

type matchDetail struct {
	Type       string            `json:"type"`
	Matcher    string            `json:"matcher"`
	SearchedBy map[string]string `json:"searchedBy"`
	Found      map[string]string `json:"found"`
}

type componentIdentity struct {
	Name      string
	Version   string
	PURL      string
	PURLType  string
	Ecosystem string
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("%s %s\nupstream: %s %s\nmode: offline-local-v6\n", scannerName, scannerVersion, upstreamName, upstreamVersion)
		return
	}

	fs := flag.NewFlagSet(scannerName, flag.ExitOnError)
	sbomPath := fs.String("sbom", "", "CycloneDX 1.5 SBOM path")
	dbDir := fs.String("db-dir", "", "directory containing vulnerability.db")
	outputPath := fs.String("output", "", "output Grype-compatible JSON path")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fatal(err)
	}

	if strings.TrimSpace(*sbomPath) == "" || strings.TrimSpace(*dbDir) == "" || strings.TrimSpace(*outputPath) == "" {
		fatal(errors.New("--sbom, --db-dir, and --output are required"))
	}

	if err := run(*sbomPath, *dbDir, *outputPath); err != nil {
		fatal(err)
	}
}

func run(sbomPath, dbDir, outputPath string) error {
	sbomAbs, err := filepath.Abs(sbomPath)
	if err != nil {
		return fmt.Errorf("resolve sbom path: %w", err)
	}
	dbAbs, err := filepath.Abs(dbDir)
	if err != nil {
		return fmt.Errorf("resolve db directory: %w", err)
	}
	outAbs, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}

	if sbomAbs == outAbs {
		return errors.New("output path must differ from SBOM path")
	}

	dbFile := filepath.Join(dbAbs, v6.VulnerabilityDBFileName)
	info, err := os.Stat(dbFile)
	if err != nil {
		return fmt.Errorf("required Grype v6 database missing: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return errors.New("required Grype v6 database is not a non-empty regular file")
	}

	doc, err := readSBOM(sbomAbs)
	if err != nil {
		return err
	}

	reader, err := v6.NewReader(v6.Config{DBDirPath: dbAbs, Debug: false})
	if err != nil {
		return fmt.Errorf("open Grype v6 database read-only: %w", err)
	}
	defer reader.Close()

	matches := make([]grypeMatch, 0)
	for i, component := range doc.Components {
		if strings.EqualFold(strings.TrimSpace(component.Type), "file") && strings.TrimSpace(component.PURL) == "" {
			continue
		}
		identity, err := normalizeComponent(component)
		if err != nil {
			return fmt.Errorf("component %d: %w", i, err)
		}
		found, err := matchComponent(reader, identity)
		if err != nil {
			return fmt.Errorf("component %s@%s: %w", identity.Name, identity.Version, err)
		}
		matches = append(matches, found...)
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Vulnerability.ID != matches[j].Vulnerability.ID {
			return matches[i].Vulnerability.ID < matches[j].Vulnerability.ID
		}
		if matches[i].Artifact.PURL != matches[j].Artifact.PURL {
			return matches[i].Artifact.PURL < matches[j].Artifact.PURL
		}
		return matches[i].Artifact.Version < matches[j].Artifact.Version
	})

	result := grypeDocument{
		Descriptor: descriptor{Name: "grype", Version: upstreamVersion},
		Matches:    matches,
		Source:     sourceInfo{Type: "sbom", Target: sbomAbs},
	}
	return writeAtomicJSON(outAbs, result)
}

func readSBOM(path string) (cycloneDXDocument, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return cycloneDXDocument{}, fmt.Errorf("read CycloneDX SBOM: %w", err)
	}

	var doc cycloneDXDocument
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	if err := decoder.Decode(&doc); err != nil {
		return cycloneDXDocument{}, fmt.Errorf("parse CycloneDX SBOM: %w", err)
	}

	if doc.BOMFormat != "CycloneDX" {
		return cycloneDXDocument{}, fmt.Errorf("unsupported SBOM bomFormat %q", doc.BOMFormat)
	}
	if doc.SpecVersion != "1.5" {
		return cycloneDXDocument{}, fmt.Errorf("unsupported CycloneDX specVersion %q", doc.SpecVersion)
	}
	if doc.Components == nil {
		return cycloneDXDocument{}, errors.New("CycloneDX components are required")
	}
	return doc, nil
}

func normalizeComponent(c cycloneDXComponent) (componentIdentity, error) {
	if strings.TrimSpace(c.Name) == "" {
		return componentIdentity{}, errors.New("component name is required")
	}
	if strings.TrimSpace(c.Version) == "" {
		return componentIdentity{}, errors.New("component version is required")
	}
	if strings.TrimSpace(c.PURL) == "" {
		return componentIdentity{}, errors.New("component purl is required")
	}

	p, err := packageurl.FromString(c.PURL)
	if err != nil {
		return componentIdentity{}, fmt.Errorf("invalid purl %q: %w", c.PURL, err)
	}

	ecosystem, err := ecosystemForPURLType(p.Type)
	if err != nil {
		return componentIdentity{}, err
	}

	name := c.Name
	if p.Name != "" {
		name = p.Name
	}
	if p.Namespace != "" && p.Type == packageurl.TypeMaven {
		name = p.Namespace + ":" + p.Name
	}

	return componentIdentity{
		Name:      name,
		Version:   c.Version,
		PURL:      c.PURL,
		PURLType:  p.Type,
		Ecosystem: ecosystem,
	}, nil
}

func ecosystemForPURLType(purlType string) (string, error) {
	switch strings.ToLower(purlType) {
	case packageurl.TypeNPM:
		return "npm", nil
	case packageurl.TypePyPi:
		return "python", nil
	case packageurl.TypeGolang:
		return "golang", nil
	case packageurl.TypeMaven:
		return "java", nil
	case packageurl.TypeCargo:
		return "rust", nil
	case packageurl.TypeConan:
		return "conan", nil
	default:
		return "", fmt.Errorf("unsupported package ecosystem %q; required coverage fails closed", purlType)
	}
}

func matchComponent(reader v6.Reader, component componentIdentity) ([]grypeMatch, error) {
	spec := &v6.PackageSpecifier{Name: component.Name, Ecosystem: component.Ecosystem}
	opts := &v6.GetPackageOptions{
		PreloadPackage:       true,
		PreloadVulnerability: true,
		PreloadBlob:          true,
	}

	affected, err := reader.GetAffectedPackages(spec, opts)
	if err != nil {
		return nil, fmt.Errorf("query affected package records: %w", err)
	}
	unaffected, err := reader.GetUnaffectedPackages(spec, opts)
	if err != nil {
		return nil, fmt.Errorf("query unaffected package records: %w", err)
	}

	suppressed := make(map[v6.ID]bool)
	for i := range unaffected {
		ok, err := recordApplies(unaffected[i].BlobValue, component.Version)
		if err != nil {
			return nil, fmt.Errorf("evaluate unaffected record %d: %w", unaffected[i].ID, err)
		}
		if ok {
			suppressed[unaffected[i].VulnerabilityID] = true
		}
	}

	var matches []grypeMatch
	for i := range affected {
		record := affected[i]
		if suppressed[record.VulnerabilityID] {
			continue
		}

		ok, err := recordApplies(record.BlobValue, component.Version)
		if err != nil {
			return nil, fmt.Errorf("evaluate affected record %d: %w", record.ID, err)
		}
		if !ok {
			continue
		}
		if record.Vulnerability == nil {
			return nil, fmt.Errorf("affected record %d missing preloaded vulnerability", record.ID)
		}

		vulns, err := reader.GetVulnerabilities(
			&v6.VulnerabilitySpecifier{ID: record.VulnerabilityID},
			&v6.GetVulnerabilityOptions{Preload: true, Limit: 2},
		)
		if err != nil {
			return nil, fmt.Errorf("load vulnerability %d: %w", record.VulnerabilityID, err)
		}
		if len(vulns) != 1 {
			return nil, fmt.Errorf("expected exactly one vulnerability for id %d, got %d", record.VulnerabilityID, len(vulns))
		}

		vuln := vulns[0]
		if strings.EqualFold(strings.TrimSpace(string(vuln.Status)), "rejected") || vuln.WithdrawnDate != nil {
			continue
		}
		if vuln.BlobValue == nil {
			return nil, fmt.Errorf("vulnerability %s missing blob", vuln.Name)
		}

		fixed := fixedVersions(record.BlobValue)
		aliases := uniqueSorted(vuln.BlobValue.Aliases)
		related := make([]relatedVulnerability, 0, len(aliases))
		for _, alias := range aliases {
			related = append(related, relatedVulnerability{ID: alias})
		}

		matches = append(matches, grypeMatch{
			Vulnerability: grypeVulnerability{
				ID:          vuln.Name,
				DataSource:  vuln.ProviderID,
				Namespace:   vuln.ProviderID,
				Severity:    severity(vuln.BlobValue),
				Description: vuln.BlobValue.Description,
				Fix: fixInfo{
					Versions: fixed,
					State:    fixState(fixed),
				},
			},
			RelatedVulnerabilities: related,
			Artifact: grypeArtifact{
				Name:      component.Name,
				Version:   component.Version,
				PURL:      component.PURL,
				Type:      component.PURLType,
				Locations: []location{},
			},
			MatchDetails: []matchDetail{{
				Type:    "exact-direct-match",
				Matcher: "quilons-controlled-grype-v6",
				SearchedBy: map[string]string{
					"package":   component.Name,
					"version":   component.Version,
					"ecosystem": component.Ecosystem,
				},
				Found: map[string]string{
					"vulnerability": vuln.Name,
					"provider":      vuln.ProviderID,
				},
			}},
		})
	}

	return matches, nil
}

func recordApplies(blob *v6.PackageBlob, versionString string) (bool, error) {
	if blob == nil {
		return false, errors.New("package record blob missing")
	}
	if len(blob.Ranges) == 0 {
		return false, errors.New("package record has no version ranges")
	}

	for _, r := range blob.Ranges {
		if strings.TrimSpace(r.Version.Constraint) == "" {
			return true, nil
		}
		format := grypeVersion.ParseFormat(r.Version.Type)
		if format == grypeVersion.UnknownFormat {
			return false, fmt.Errorf("unsupported Grype version format %q", r.Version.Type)
		}
		constraint, err := grypeVersion.GetConstraint(r.Version.Constraint, format)
		if err != nil {
			return false, fmt.Errorf("parse constraint %q (%s): %w", r.Version.Constraint, r.Version.Type, err)
		}
		ok, err := constraint.Satisfied(grypeVersion.New(versionString, format))
		if err != nil {
			return false, fmt.Errorf("evaluate constraint %q against %q: %w", r.Version.Constraint, versionString, err)
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func fixedVersions(blob *v6.PackageBlob) []string {
	if blob == nil {
		return []string{}
	}
	var versions []string
	for _, r := range blob.Ranges {
		if r.Fix == nil || strings.TrimSpace(r.Fix.Version) == "" {
			continue
		}
		if strings.EqualFold(string(r.Fix.State), "fixed") {
			versions = append(versions, strings.TrimSpace(r.Fix.Version))
		}
	}
	return uniqueSorted(versions)
}

func fixState(versions []string) string {
	if len(versions) > 0 {
		return "fixed"
	}
	return "not-fixed"
}

func severity(blob *v6.VulnerabilityBlob) string {
	if blob == nil || len(blob.Severities) == 0 {
		return "unknown"
	}
	for _, s := range blob.Severities {
		if value, ok := s.Value.(string); ok {
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "critical", "high", "medium", "low", "negligible", "unknown":
				return strings.ToLower(strings.TrimSpace(value))
			}
		}
	}
	return "unknown"
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{})
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func writeAtomicJSON(path string, value any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".quilons-grype-*.json")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()

	enc := json.NewEncoder(tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return fmt.Errorf("encode output: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("set output permissions: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace output: %w", err)
	}
	ok = true
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
