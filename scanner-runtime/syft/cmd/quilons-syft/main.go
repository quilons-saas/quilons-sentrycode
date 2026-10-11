package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/alpine"
	"github.com/anchore/syft/syft/pkg/cataloger/cpp"
	"github.com/anchore/syft/syft/pkg/cataloger/debian"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/pkg/cataloger/redhat"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

const (
	scannerName      = "quilons-controlled-syft"
	scannerVersion   = "1.54.0-quilons.6"
	upstreamVersion  = "v1.54.0"
	upstreamCommit   = "cc326e45a6213360266dda4b30cc68095946d676"
	cycloneDXVersion = "1.5"
	coverageIdentity = "javascript-npm,python,rust,c-cpp,go,java,linux-os,alpine-apk,debian-dpkg,redhat-rpm"
)

type catalogerSpec struct {
	name      string
	cataloger pkg.Cataloger
}

type versionInfo struct {
	Scanner        string `json:"scanner"`
	Version        string `json:"version"`
	Upstream       string `json:"upstream"`
	UpstreamCommit string `json:"upstreamCommit"`
	OutputFormat   string `json:"outputFormat"`
	NetworkPolicy  string `json:"networkPolicy"`
	SourcePolicy   string `json:"sourcePolicy"`
	Coverage       string `json:"coverage"`
	Encoder        string `json:"encoder"`
}

type cdxBom struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	Version      int             `json:"version"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

type cdxMetadata struct {
	Tools      []cdxTool     `json:"tools"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxComponent struct {
	Type        string             `json:"type"`
	BOMRef      string             `json:"bom-ref"`
	Name        string             `json:"name"`
	Version     string             `json:"version,omitempty"`
	PURL        string             `json:"purl,omitempty"`
	Description string             `json:"description,omitempty"`
	CPE         string             `json:"cpe,omitempty"`
	Properties  []cdxProperty      `json:"properties,omitempty"`
	Licenses    []cdxLicenseChoice `json:"licenses,omitempty"`
}

type cdxLicenseChoice struct {
	License cdxLicense `json:"license"`
}

type cdxLicense struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet(scannerName, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	input := fs.String("input", "", "directory to inventory")
	output := fs.String("output", "", "CycloneDX JSON output path")
	showVersion := fs.Bool("version", false, "print scanner identity as JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	if *showVersion {
		return json.NewEncoder(os.Stdout).Encode(versionInfo{
			Scanner:        scannerName,
			Version:        scannerVersion,
			Upstream:       upstreamVersion,
			UpstreamCommit: upstreamCommit,
			OutputFormat:   "cyclonedx-json@1.5",
			NetworkPolicy:  "offline",
			SourcePolicy:   "directory-only",
			Coverage:       coverageIdentity,
			Encoder:        "quilons-native-cyclonedx",
		})
	}

	if strings.TrimSpace(*input) == "" {
		return errors.New("--input is required")
	}
	if strings.TrimSpace(*output) == "" {
		return errors.New("--output is required")
	}

	inputAbs, err := filepath.Abs(*input)
	if err != nil {
		return fmt.Errorf("resolve input path: %w", err)
	}
	info, err := os.Stat(inputAbs)
	if err != nil {
		return fmt.Errorf("stat input path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("input must be a directory: %s", inputAbs)
	}

	outputAbs, err := filepath.Abs(*output)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}

	src, err := directorysource.NewFromPath(inputAbs)
	if err != nil {
		return fmt.Errorf("create directory source: %w", err)
	}
	defer src.Close()

	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		return fmt.Errorf("create directory resolver: %w", err)
	}

	ctx, cleanupTempDir := cataloging.WithQuilonsTempDir(ctx, "quilons-syft")
	defer func() {
		_ = cleanupTempDir()
	}()

	collection := pkg.NewCollection()
	var relationships []artifact.Relationship

	for _, spec := range offlineCatalogers() {
		packages, rels, catalogErr := spec.cataloger.Catalog(ctx, resolver)
		if catalogErr != nil {
			return fmt.Errorf("cataloger %s failed: %w", spec.name, catalogErr)
		}
		collection.Add(packages...)
		relationships = append(relationships, rels...)
	}

	distro := linux.IdentifyRelease(resolver)
	bom := buildCycloneDX(collection, relationships, distro)

	parent := filepath.Dir(outputAbs)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	temp, err := os.CreateTemp(parent, ".quilons-syft-*.json")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	tempName := temp.Name()
	committed := false
	defer func() {
		_ = temp.Close()
		if !committed {
			_ = os.Remove(tempName)
		}
	}()

	encoder := json.NewEncoder(temp)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(bom); err != nil {
		return fmt.Errorf("encode CycloneDX inventory: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync CycloneDX inventory: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close CycloneDX inventory: %w", err)
	}
	if err := os.Chmod(tempName, 0o644); err != nil {
		return fmt.Errorf("set CycloneDX inventory permissions: %w", err)
	}
	if err := os.Rename(tempName, outputAbs); err != nil {
		return fmt.Errorf("commit CycloneDX inventory: %w", err)
	}

	committed = true
	return nil
}

func offlineCatalogers() []catalogerSpec {
	javascriptConfig := javascript.DefaultCatalogerConfig().
		WithSearchRemoteLicenses(false).
		WithIncludeDevDependencies(true)

	goConfig := golang.DefaultCatalogerConfig().
		WithSearchRemoteLicenses(false).
		WithSearchLocalModCacheLicenses(false).
		WithSearchLocalVendorLicenses(false).
		WithUsePackagesLib(false)

	javaConfig := java.DefaultArchiveCatalogerConfig().
		WithUseNetwork(false).
		WithUseMavenLocalRepository(false).
		WithResolveTransitiveDependencies(false)

	pythonConfig := python.DefaultCatalogerConfig().
		WithSearchRemoteLicenses(false).
		WithGuessUnpinnedRequirements(false)

	cppConfig := cpp.DefaultCatalogerConfig().
		WithVcpkgAllowGitClone(false)

	return []catalogerSpec{
		{name: "javascript-package", cataloger: javascript.NewPackageCataloger()},
		{name: "javascript-lock", cataloger: javascript.NewLockCataloger(javascriptConfig)},
		{name: "go-module-file", cataloger: golang.NewGoModuleFileCataloger(goConfig)},
		{name: "java-pom", cataloger: java.NewPomCataloger(javaConfig)},
		{name: "java-gradle-lock", cataloger: java.NewGradleLockfileCataloger()},
		{name: "python-package", cataloger: python.NewPackageCataloger(pythonConfig)},
		{name: "rust-cargo-lock", cataloger: rust.NewCargoLockCataloger()},
		{name: "linux-alpine-apk-db", cataloger: alpine.NewDBCataloger()},
		{name: "linux-debian-dpkg-db", cataloger: debian.NewDBCataloger()},
		{name: "linux-redhat-rpm-db", cataloger: redhat.NewDBCataloger()},
		{name: "cpp-conan", cataloger: cpp.NewConanCataloger()},
		{name: "cpp-conan-info", cataloger: cpp.NewConanInfoCataloger()},
		{name: "cpp-vcpkg-manifest", cataloger: cpp.NewVcpkgManifestCataloger(cppConfig)},
	}
}

func buildCycloneDX(collection *pkg.Collection, relationships []artifact.Relationship, distro *linux.Release) cdxBom {
	packages := collection.Sorted()
	components := make([]cdxComponent, 0, len(packages))
	refByID := make(map[artifact.ID]string, len(packages))

	for index, p := range packages {
		ref := componentRef(p, index)
		refByID[p.ID()] = ref

		component := cdxComponent{
			Type:    "library",
			BOMRef:  ref,
			Name:    p.Name,
			Version: p.Version,
			PURL:    p.PURL,
			Properties: []cdxProperty{
				{Name: "quilons:syft:package-type", Value: p.Type.String()},
				{Name: "quilons:syft:found-by", Value: p.FoundBy},
				{Name: "quilons:syft:language", Value: p.Language.String()},
			},
		}

		for _, license := range p.Licenses.ToSlice() {
			if license.SPDXExpression != "" {
				component.Licenses = append(component.Licenses, cdxLicenseChoice{
					License: cdxLicense{ID: license.SPDXExpression},
				})
				continue
			}
			if license.Value != "" {
				component.Licenses = append(component.Licenses, cdxLicenseChoice{
					License: cdxLicense{Name: license.Value},
				})
			}
		}

		components = append(components, component)
	}

	dependencySets := map[string]map[string]struct{}{}
	for _, rel := range relationships {
		if rel.Type != artifact.DependencyOfRelationship {
			continue
		}

		dependencyRef, dependencyOK := refByID[rel.From.ID()]
		parentRef, parentOK := refByID[rel.To.ID()]
		if !dependencyOK || !parentOK || dependencyRef == parentRef {
			continue
		}

		if dependencySets[parentRef] == nil {
			dependencySets[parentRef] = map[string]struct{}{}
		}
		dependencySets[parentRef][dependencyRef] = struct{}{}
	}

	dependencies := make([]cdxDependency, 0, len(dependencySets))
	for parentRef, children := range dependencySets {
		dependsOn := make([]string, 0, len(children))
		for childRef := range children {
			dependsOn = append(dependsOn, childRef)
		}
		sort.Strings(dependsOn)
		dependencies = append(dependencies, cdxDependency{
			Ref:       parentRef,
			DependsOn: dependsOn,
		})
	}
	sort.Slice(dependencies, func(i, j int) bool {
		return dependencies[i].Ref < dependencies[j].Ref
	})

	if distro != nil && (strings.TrimSpace(distro.ID) != "" || strings.TrimSpace(distro.VersionID) != "") {
		osName := strings.TrimSpace(distro.ID)
		if osName == "" {
			osName = strings.TrimSpace(distro.Name)
		}
		osVersion := strings.TrimSpace(distro.VersionID)
		if osVersion == "" {
			osVersion = strings.TrimSpace(distro.Version)
		}

		osRef := "os:" + osName
		if osVersion != "" {
			osRef += "@" + osVersion
		}

		properties := []cdxProperty{
			{Name: "syft:distro:id", Value: distro.ID},
			{Name: "syft:distro:versionID", Value: distro.VersionID},
		}
		if distro.PrettyName != "" {
			properties = append(properties, cdxProperty{Name: "syft:distro:prettyName", Value: distro.PrettyName})
		}
		if len(distro.IDLike) > 0 {
			properties = append(properties, cdxProperty{Name: "syft:distro:idLike", Value: strings.Join(distro.IDLike, ",")})
		}

		components = append(components, cdxComponent{
			Type:        "operating-system",
			BOMRef:      osRef,
			Name:        osName,
			Version:     osVersion,
			Description: distro.PrettyName,
			CPE:         distro.CPEName,
			Properties:  properties,
		})
	}

	return cdxBom{
		BOMFormat:   "CycloneDX",
		SpecVersion: cycloneDXVersion,
		Version:     1,
		Metadata: cdxMetadata{
			Tools: []cdxTool{
				{
					Vendor:  "QUILONS",
					Name:    scannerName,
					Version: scannerVersion,
				},
			},
			Properties: []cdxProperty{
				{Name: "quilons:scanner:upstream", Value: upstreamVersion},
				{Name: "quilons:scanner:upstream-commit", Value: upstreamCommit},
				{Name: "quilons:scanner:network-policy", Value: "offline"},
				{Name: "quilons:scanner:source-policy", Value: "directory-only"},
				{Name: "quilons:scanner:coverage", Value: coverageIdentity},
			},
		},
		Components:   components,
		Dependencies: dependencies,
	}
}

func componentRef(p pkg.Package, index int) string {
	if p.PURL != "" {
		return p.PURL
	}
	if id := string(p.ID()); id != "" {
		return "urn:quilons:syft:" + id
	}
	return fmt.Sprintf("urn:quilons:syft:%s:%s:%d", p.Name, p.Version, index)
}
