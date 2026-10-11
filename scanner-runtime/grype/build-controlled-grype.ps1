Clear-Host

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

$ErrorActionPreference = 'Stop'

$Repo = 'C:\Sajith\Quilons AI\quilons-sentrycode'
$GoImage = 'golang@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107'
$ImageTag = 'quilons-controlled-grype:slice2c-a15'

function Fail([string]$Message) {
    Write-Host "FAILED: $Message" -ForegroundColor Red
    throw $Message
}

Set-Location $Repo

$Base = Join-Path $Repo 'scanner-runtime\grype'
$Work = Join-Path $env:TEMP ('quilons-controlled-grype-a15-' + [guid]::NewGuid().ToString('N'))
$BuildSucceeded = $false
New-Item -ItemType Directory -Force -Path $Work | Out-Null

try {
    Copy-Item -LiteralPath (Join-Path $Base 'cmd\quilons-grype\main.go') -Destination (Join-Path $Work 'main.go')
    Copy-Item -LiteralPath (Join-Path $Base 'tools\patch-grype.mjs') -Destination (Join-Path $Work 'patch-grype.mjs')
    Copy-Item -LiteralPath (Join-Path $Base 'tools\verify-policy-modules.mjs') -Destination (Join-Path $Work 'verify-policy-modules.mjs')
    Copy-Item -LiteralPath (Join-Path $Base 'Dockerfile.controlled') -Destination (Join-Path $Work 'Dockerfile')

    $Probe = @'
set -eu

# A34: bounded retry for transient Go module/proxy/DNS failures.
# Build harness only: source reductions, command semantics, and L-01 policy are unchanged.
retry_go() {
  max_attempts=5
  attempt=1
  while true; do
    if "$@"; then
      return 0
    else
      status=$?
    fi

    if [ "$attempt" -ge "$max_attempts" ]; then
      echo "A34 Go command failed after ${attempt}/${max_attempts} attempts: $*" >&2
      return "$status"
    fi

    delay=$((attempt * 5))
    echo "A34 transient Go command failure (${attempt}/${max_attempts}); retrying in ${delay}s: $*" >&2
    sleep "$delay"
    attempt=$((attempt + 1))
  done
}

retry_go_json() {
  output="$1"
  shift
  tmp="${output}.a34-attempt"
  rm -f "$tmp"

  max_attempts=5
  attempt=1
  while true; do
    if "$@" > "$tmp"; then
      mv "$tmp" "$output"
      return 0
    else
      status=$?
    fi

    rm -f "$tmp"

    if [ "$attempt" -ge "$max_attempts" ]; then
      echo "A34 Go JSON command failed after ${attempt}/${max_attempts} attempts: $*" >&2
      return "$status"
    fi

    delay=$((attempt * 5))
    echo "A34 transient Go JSON command failure (${attempt}/${max_attempts}); retrying in ${delay}s: $*" >&2
    sleep "$delay"
    attempt=$((attempt + 1))
  done
}

go version

retry_go_json /work/grype-download.json go mod download -json github.com/anchore/grype@v0.120.0
retry_go_json /work/syft-download.json go mod download -json github.com/anchore/syft@v1.54.0

MODCACHE="$(go env GOMODCACHE)"
GRYPE_SRC="$MODCACHE/github.com/anchore/grype@v0.120.0"
SYFT_SRC="$MODCACHE/github.com/anchore/syft@v1.54.0"

test -d "$GRYPE_SRC"
test -d "$SYFT_SRC"

cp -a "$GRYPE_SRC" /tmp/grype
cp -a "$SYFT_SRC" /tmp/syft
chmod -R u+w /tmp/grype /tmp/syft

# Reuse the already accepted Syft file/location policy reduction because Grype version format imports syft/pkg.
LOCATION=/tmp/syft/syft/file/location.go
test "$(grep -F -c '"github.com/hashicorp/go-multierror"' "$LOCATION" || true)" = "1"
test "$(grep -F -c 'errs = multierror.Append(errs, err)' "$LOCATION" || true)" = "1"

awk 'BEGIN{i=0;r=0;p=0} {
  if ($0 == "\t\"fmt\"") { print "\t\"errors\""; i++ }
  if ($0 == "\t\"github.com/hashicorp/go-multierror\"") { r++; next }
  if ($0 ~ /errs = multierror\.Append\(errs, err\)/) {
    sub(/errs = multierror\.Append\(errs, err\)/, "errs = errors.Join(errs, err)")
    p++
  }
  print
}
END { if (i != 1 || r != 1 || p != 1) exit 42 }' "$LOCATION" > "$LOCATION.tmp"
mv "$LOCATION.tmp" "$LOCATION"

# A15 FIX2: deterministic Grype source reductions using builder-native POSIX tools.
PROVIDER=/tmp/grype/grype/db/v6/vulnerability_provider.go
test -f "$PROVIDER"
grep -F 'func NewVulnerabilityProvider' "$PROVIDER" >/dev/null
mv "$PROVIDER" "$PROVIDER.disabled"

for FILE in \
  /tmp/grype/grype/version/bitnami_version.go \
  /tmp/grype/grype/version/fuzzy_constraint.go \
  /tmp/grype/grype/version/golang_version.go \
  /tmp/grype/grype/version/jvm_version.go \
  /tmp/grype/grype/version/semantic_version.go
do
  test -f "$FILE"
  COUNT="$(grep -F -c 'hashiVer "github.com/anchore/go-version"' "$FILE" || true)"
  test "$COUNT" = "1"
  sed -i 's#hashiVer "github.com/anchore/go-version"#hashiVer "github.com/Masterminds/semver/v3"#' "$FILE"
  ! grep -F 'hashiVer "github.com/anchore/go-version"' "$FILE"
done

GO_VERSION=/tmp/grype/grype/version/golang_version.go
COUNT="$(grep -F -c 'hashiVer.NewSemver(fixedUp)' "$GO_VERSION" || true)"
test "$COUNT" = "1"
sed -i 's/hashiVer\.NewSemver(fixedUp)/hashiVer.StrictNewVersion(fixedUp)/' "$GO_VERSION"

SEMANTIC_VERSION=/tmp/grype/grype/version/semantic_version.go
COUNT="$(grep -F -c 'hashiVer.NewSemver(clean)' "$SEMANTIC_VERSION" || true)"
test "$COUNT" = "1"
sed -i 's/hashiVer\.NewSemver(clean)/hashiVer.StrictNewVersion(clean)/' "$SEMANTIC_VERSION"

BITNAMI=/tmp/grype/grype/version/bitnami_version.go
COUNT="$(grep -F -c 'for _, segment := range verObj.Segments() {' "$BITNAMI" || true)"
test "$COUNT" = "1"
python3 - "$BITNAMI" <<'PY_BITNAMI'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()

old = """\t\tvar segments []string
\t\tfor _, segment := range verObj.Segments() {
\t\t\tsegments = append(segments, fmt.Sprintf("%d", segment))
\t\t}
\t\t// drop any pre-release info
\t\traw = strings.Join(segments, ".")
"""

new = """\t\t// drop any pre-release/build info while preserving the numeric release tuple
\t\traw = fmt.Sprintf("%d.%d.%d", verObj.Major(), verObj.Minor(), verObj.Patch())
"""

if text.count(old) != 1:
    raise SystemExit("bitnami Segments() source drift")

text = text.replace(old, new)

strings_import = '\n\t"strings"\n'
if text.count(strings_import) != 1:
    raise SystemExit("bitnami strings import source drift")

text = text.replace(strings_import, '\n', 1)
path.write_text(text)
PY_BITNAMI
! grep -F 'verObj.Segments()' "$BITNAMI"
! grep -F '"strings"' "$BITNAMI"

FUZZY=/tmp/grype/grype/version/fuzzy_constraint.go
COUNT="$(grep -F -c 'semverConstraint = &value' "$FUZZY" || true)"
test "$COUNT" = "1"
sed -i 's/semverConstraint = &value/semverConstraint = value/' "$FUZZY"

! grep -R -n --include='*.go' -F '"github.com/anchore/go-version"' /tmp/grype/grype/version

echo '{"status":"pass","patcher":"posix-shell","disabled":["grype/db/v6/vulnerability_provider.go"],"semverReplacement":"github.com/Masterminds/semver/v3"}'

# A16: controlled read-only v6 package reduction.
# The scanner needs only local DB opening plus affected/unaffected package and vulnerability reads.
# These files are conversion/build/update/provenance helpers that pull broad Grype/Syft or downloader paths.
for FILE in \
  /tmp/grype/grype/db/v6/data.go \
  /tmp/grype/grype/db/v6/import_metadata.go \
  /tmp/grype/grype/db/v6/vulnerability.go
do
  test -f "$FILE"
  mv "$FILE" "$FILE.disabled"
done

# vulnerability_provider.go was already disabled above.
test -f /tmp/grype/grype/db/v6/vulnerability_provider.go.disabled

cat > /tmp/grype/grype/db/v6/db.go <<'GO_DB'
package v6

import (
	"fmt"
	"io"
	"path/filepath"

	"gorm.io/gorm"

	"github.com/anchore/grype/grype/db/internal/gormadapter"
)

const (
	ModelVersion = 6
	Revision = 1
	Addition = 10
	VulnerabilityDBFileName = "vulnerability.db"
	batchSize = 300
)

var ErrDBCapabilityNotSupported = fmt.Errorf("capability not supported by DB")

type Reader interface {
	DBMetadataStoreReader
	ProviderStoreReader
	VulnerabilityStoreReader
	OperatingSystemStoreReader
	AffectedPackageStoreReader
	UnaffectedPackageStoreReader
	io.Closer
	attachBlobValue(...blobable) error
}

type Config struct {
	DBDirPath string
	Debug bool
}

func (c Config) DBFilePath() string {
	return filepath.Join(c.DBDirPath, VulnerabilityDBFileName)
}

func NewReader(cfg Config) (Reader, error) {
	return newReadOnlyStore(cfg)
}

func NewLowLevelDB(dbFilePath string, debug bool) (*gorm.DB, error) {
	return gormadapter.Open(dbFilePath, gormadapter.WithDebug(debug))
}
GO_DB

cat > /tmp/grype/grype/db/v6/store.go <<'GO_STORE'
package v6

import (
	"fmt"

	"gorm.io/gorm"
)

type store struct {
	*dbMetadataStore
	*providerStore
	*vulnerabilityStore
	*operatingSystemStore
	*affectedPackageStore
	*unaffectedPackageStore
	blobStore *blobStore
	db *gorm.DB
	config Config
}

func newReadOnlyStore(cfg Config) (*store, error) {
	if cfg.DBDirPath == "" {
		return nil, fmt.Errorf("database directory is required")
	}

	db, err := NewLowLevelDB(cfg.DBFilePath(), cfg.Debug)
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}

	closeOnError := func() {
		sqlDB, sqlErr := db.DB()
		if sqlErr == nil && sqlDB != nil {
			_ = sqlDB.Close()
		}
	}

	metadataStore := newDBMetadataStore(db)
	meta, err := metadataStore.GetDBMetadata()
	if err != nil {
		closeOnError()
		return nil, fmt.Errorf("failed to read db metadata: %w", err)
	}
	if meta == nil || meta.Model != ModelVersion {
		closeOnError()
		return nil, fmt.Errorf("not a v%d database", ModelVersion)
	}

	bs := newBlobStore(db)
	osStore := newOperatingSystemStore(db, bs)

	return &store{
		dbMetadataStore: metadataStore,
		providerStore: newProviderStore(db),
		vulnerabilityStore: newVulnerabilityStore(db, bs),
		operatingSystemStore: osStore,
		affectedPackageStore: newAffectedPackageStore(db, bs, osStore),
		unaffectedPackageStore: newUnaffectedPackageStore(db, bs, osStore),
		blobStore: bs,
		db: db,
		config: cfg,
	}, nil
}

func (s *store) GetDB() *gorm.DB {
	return s.db
}

func (s *store) attachBlobValue(values ...blobable) error {
	return s.blobStore.attachBlobValue(values...)
}

func (s *store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
GO_STORE

# Fail closed if any excluded production file is accidentally restored.
for FILE in data.go import_metadata.go vulnerability.go vulnerability_provider.go; do
  test ! -f "/tmp/grype/grype/db/v6/$FILE"
  test -f "/tmp/grype/grype/db/v6/$FILE.disabled"
done

echo '{"status":"pass","v6Mode":"read-only-reduced","excluded":["data.go","import_metadata.go","vulnerability.go","vulnerability_provider.go"]}'

cd /tmp/grype
go mod edit -replace=github.com/anchore/syft=/tmp/syft

mkdir -p /tmp/wrapper
cp /work/main.go /tmp/wrapper/main.go

cat > /tmp/wrapper/go.mod <<'EOF'
module quilons.local/controlled-grype

go 1.26.0

require (
    github.com/anchore/grype v0.120.0
    github.com/anchore/packageurl-go v0.2.0
)

replace github.com/anchore/grype => /tmp/grype
replace github.com/anchore/syft => /tmp/syft
EOF

cd /tmp/wrapper
retry_go go mod tidy
# A18 FIX6: exact post-A17 residual-root reduction.
# A17 proved only two compiled contamination roots remain:
#   1. grype/db/v6/name -> grype/pkg -> broad Syft graph
#   2. grype/version -> go-mvn-version -> go-multierror -> errwrap
#
# This block executes inside the existing builder-native POSIX probe immediately
# before the controlled binary build. The L-01 verifier remains unchanged.

A18_GRYPE_ROOT="/tmp/grype"

# A22 FIX1: A18 must mutate the exact source tree compiled by the wrapper:
#   replace github.com/anchore/grype => /tmp/grype
# The earlier module-cache discovery selected github.com/anchore/grype@v0.120.0
# instead, so A18 mutated a different tree while go build compiled /tmp/grype.
if [ ! -d "$A18_GRYPE_ROOT" ]; then
  echo "A18 authoritative Grype build root missing: $A18_GRYPE_ROOT" >&2
  exit 91
fi

if [ ! -f "$A18_GRYPE_ROOT/go.mod" ]; then
  echo "A18 authoritative Grype go.mod missing: $A18_GRYPE_ROOT/go.mod" >&2
  exit 91
fi

grep -F 'module github.com/anchore/grype' "$A18_GRYPE_ROOT/go.mod" >/dev/null || {
  echo "A18 authoritative build root is not the Grype module" >&2
  exit 91
}

A18_NAME_DIR="$A18_GRYPE_ROOT/grype/db/v6/name"
A18_VERSION_DIR="$A18_GRYPE_ROOT/grype/version"

for f in \
  "$A18_NAME_DIR/resolver.go" \
  "$A18_NAME_DIR/java.go" \
  "$A18_NAME_DIR/python.go" \
  "$A18_VERSION_DIR/maven_version.go"
do
  if [ ! -f "$f" ]; then
    echo "A18 required source missing: $f" >&2
    exit 92
  fi
done

grep -F 'github.com/anchore/grype/grype/pkg' "$A18_NAME_DIR/resolver.go" >/dev/null || {
  echo "A18 root-1 source guard failed: grype/pkg import missing" >&2
  exit 93
}

grep -F 'github.com/anchore/syft/syft/pkg' "$A18_NAME_DIR/resolver.go" >/dev/null || {
  echo "A18 root-1 source guard failed: syft/pkg import missing" >&2
  exit 94
}

grep -F 'github.com/masahiro331/go-mvn-version' "$A18_VERSION_DIR/maven_version.go" >/dev/null || {
  echo "A18 root-2 source guard failed: go-mvn-version import missing" >&2
  exit 95
}

cat > "$A18_NAME_DIR/resolver.go" <<'A18_NAME_EOF'
package name

import (
	"regexp"

	syftPkg "github.com/anchore/syft/syft/pkg"
)

var pythonNormalizePattern = regexp.MustCompile(`[-_.]+`)

// Normalize preserves the Grype v0.120.0 v6 read-query normalization contract.
// Python follows PEP 503 normalization; all other package types are unchanged.
func Normalize(value string, pkgType syftPkg.Type) string {
	if pkgType == syftPkg.PythonPkg {
		return pythonNormalizePattern.ReplaceAllString(value, "-")
	}
	return value
}
A18_NAME_EOF

mv "$A18_NAME_DIR/java.go" "$A18_NAME_DIR/java.go.disabled"
mv "$A18_NAME_DIR/python.go" "$A18_NAME_DIR/python.go.disabled"

# A37: exact upstream Maven comparison implementation.
#
# A36 differential validation proved the prior hand-reimplementation was not
# semantically equivalent (358 / 8836 pair comparisons diverged). Do not
# reimplement Maven ComparableVersion semantics here.
#
# Copy ONLY the exact Apache-2.0 version.go comparison implementation from the
# pinned upstream module into an isolated internal package. version.go imports
# only fmt, strconv and strings; comparer/constraint/requirement code is not
# copied and therefore go-multierror/errwrap are not compiled into the runtime.
A37_MVN_VERSION='v0.0.0-20250131095131-f4974fa13b8a'
A37_MODCACHE="$(go env GOMODCACHE)"
A37_UPSTREAM_DIR="$A37_MODCACHE/github.com/masahiro331/go-mvn-version@$A37_MVN_VERSION"
A37_UPSTREAM_VERSION_GO="$A37_UPSTREAM_DIR/version.go"
A37_UPSTREAM_STACK_GO="$A37_UPSTREAM_DIR/stack.go"
A37_CONTROLLED_DIR="$A18_VERSION_DIR/controlledmaven"

test -f "$A37_UPSTREAM_VERSION_GO" || {
  echo "A37 pinned upstream version.go missing: $A37_UPSTREAM_VERSION_GO" >&2
  exit 95
}

test -f "$A37_UPSTREAM_STACK_GO" || {
  echo "A37 pinned upstream stack.go missing: $A37_UPSTREAM_STACK_GO" >&2
  exit 95
}

grep -F 'package version' "$A37_UPSTREAM_VERSION_GO" >/dev/null || {
  echo "A37 upstream package guard failed" >&2
  exit 95
}

grep -F 'Qualifiers          = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}' "$A37_UPSTREAM_VERSION_GO" >/dev/null || {
  echo "A37 upstream qualifier-contract guard failed" >&2
  exit 95
}

grep -F 'Aliases             = map[string]string{"ga": "", "final": "", "release": "", "cr": "rc"}' "$A37_UPSTREAM_VERSION_GO" >/dev/null || {
  echo "A37 upstream alias-contract guard failed" >&2
  exit 95
}

if grep -E '"github\.com/|"golang\.org/|"gopkg\.in/' "$A37_UPSTREAM_VERSION_GO" >/tmp/a37-upstream-nonstdlib.txt 2>/dev/null; then
  cat /tmp/a37-upstream-nonstdlib.txt >&2
  echo "A37 upstream version.go unexpectedly imports non-stdlib packages" >&2
  exit 95
fi

rm -f "$A18_VERSION_DIR/controlled_maven_compare.go"
rm -rf "$A37_CONTROLLED_DIR"
mkdir -p "$A37_CONTROLLED_DIR"

{
  printf '%s\n' '// QUILONS controlled copy of Maven version comparison semantics.'
  printf '%s\n' '// Derived verbatim from github.com/masahiro331/go-mvn-version'
  printf '%s\n' '// commit f4974fa13b8a; upstream license: Apache-2.0.'
  printf '%s\n' '// Only package-name adaptation is applied; comparison logic is unchanged.'
  sed '0,/^package version$/s//package controlledmaven/' "$A37_UPSTREAM_VERSION_GO"
} > "$A37_CONTROLLED_DIR/version.go"

{
  printf '%s\n' '// QUILONS controlled copy of Maven version parser stack helper.'
  printf '%s\n' '// Derived verbatim from github.com/masahiro331/go-mvn-version'
  printf '%s\n' '// commit f4974fa13b8a; upstream license: Apache-2.0.'
  printf '%s\n' '// Only package-name adaptation is applied; stack logic is unchanged.'
  sed '0,/^package version$/s//package controlledmaven/' "$A37_UPSTREAM_STACK_GO"
} > "$A37_CONTROLLED_DIR/stack.go"

cat > "$A18_VERSION_DIR/maven_version.go" <<'A18_MVN_WRAP_EOF'
package version

import (
	"fmt"
	"regexp"

	controlledMaven "github.com/anchore/grype/grype/version/controlledmaven"
)

var _ Comparator = (*mavenVersion)(nil)

var javaRuntimeQualifierPattern = regexp.MustCompile(`(?i)\.(jre|jdk)\d+$`)

type mavenVersion struct {
	raw string
	obj controlledMaven.Version
}

func stripJavaRuntimeQualifier(value string) string {
	return javaRuntimeQualifierPattern.ReplaceAllString(value, "")
}

func newMavenVersion(raw string) (mavenVersion, error) {
	obj, err := controlledMaven.NewVersion(stripJavaRuntimeQualifier(raw))
	if err != nil {
		return mavenVersion{}, err
	}
	return mavenVersion{
		raw: raw,
		obj: obj,
	}, nil
}

func (v mavenVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, fmt.Errorf("cannot compare nil version with %v", other)
	}

	o, err := newMavenVersion(other.Raw)
	if err != nil {
		return 0, err
	}

	result := v.obj.Compare(o.obj)
	switch {
	case result < 0:
		return -1, nil
	case result > 0:
		return 1, nil
	default:
		return 0, nil
	}
}
A18_MVN_WRAP_EOF

gofmt -w \
  "$A18_NAME_DIR/resolver.go" \
  "$A37_CONTROLLED_DIR/version.go" \
  "$A37_CONTROLLED_DIR/stack.go" \
  "$A18_VERSION_DIR/maven_version.go"

grep -F 'package controlledmaven' "$A37_CONTROLLED_DIR/version.go" >/dev/null || {
  echo "A37 controlled package adaptation failed" >&2
  exit 95
}

grep -F 'controlledMaven "github.com/anchore/grype/grype/version/controlledmaven"' "$A18_VERSION_DIR/maven_version.go" >/dev/null || {
  echo "A37 wrapper import guard failed" >&2
  exit 95
}

if grep -R -n -E --include='*.go' --exclude='*_test.go' \
  -e '^[[:space:]]*([[:alnum:]_.]+[[:space:]]+)?"github\.com/masahiro331/go-mvn-version"' \
  -e '^[[:space:]]*([[:alnum:]_.]+[[:space:]]+)?"github\.com/hashicorp/go-multierror"' \
  -e '^[[:space:]]*([[:alnum:]_.]+[[:space:]]+)?"github\.com/hashicorp/errwrap"' \
  "$A18_VERSION_DIR" >/tmp/a37-version-blocked.txt 2>/dev/null; then
  cat /tmp/a37-version-blocked.txt >&2
  echo "A37 failed: controlled version surface still imports blocked path" >&2
  exit 97
fi

printf '%s\n' \
  '{"status":"pass","correction":"a37-exact-upstream-maven-comparator","upstream":"go-mvn-version@f4974fa13b8a","license":"Apache-2.0","policyGate":"unchanged"}'
printf '%s\n' \
  '{"status":"pass","correction":"a37-fix1-include-upstream-stack","files":["version.go","stack.go"],"policyGate":"unchanged"}'

# Source-level guards before compilation.
if grep -R -n -E --include='*.go' --exclude='*_test.go' '^[[:space:]]*([[:alnum:]_.]+[[:space:]]+)?"github\.com/anchore/grype/grype/pkg"' "$A18_NAME_DIR" >/tmp/a18-name-blocked.txt 2>/dev/null; then
  cat /tmp/a18-name-blocked.txt >&2
  echo "A18 root-1 reduction failed: db/v6/name still imports grype/pkg" >&2
  exit 96
fi

if grep -R -n -E --include='*.go' --exclude='*_test.go' \
  -e '^[[:space:]]*([[:alnum:]_.]+[[:space:]]+)?"github\.com/masahiro331/go-mvn-version"' \
  -e '^[[:space:]]*([[:alnum:]_.]+[[:space:]]+)?"github\.com/hashicorp/go-multierror"' \
  -e '^[[:space:]]*([[:alnum:]_.]+[[:space:]]+)?"github\.com/hashicorp/errwrap"' \
  "$A18_VERSION_DIR" >/tmp/a18-version-blocked.txt 2>/dev/null; then
  cat /tmp/a18-version-blocked.txt >&2
  echo "A18 root-2 reduction failed: version surface still imports blocked path" >&2
  exit 97
fi

gofmt -w \
  "$A18_NAME_DIR/resolver.go" \
  "$A18_VERSION_DIR/maven_version.go"

# A25: the post-A22 compiled graph proves the sole remaining broad dependency is:
#   grype/vulnerability/provider.go -> grype/pkg
#
# In the controlled offline v6 runtime, the provider package contracts required by
# DB read/search are Criteria, FindVulnerabilities, MetadataProvider and io.Closer.
# PackageSearchNames(grypePkg.Package) is the only production grype/pkg reference
# in this package and pulls the full Syft catalog/source graph into the binary.
A25_PROVIDER="/tmp/grype/grype/vulnerability/provider.go"

if [ ! -f "$A25_PROVIDER" ]; then
  echo "A25 required vulnerability provider source missing: $A25_PROVIDER" >&2
  exit 98
fi

grep -F 'grypePkg "github.com/anchore/grype/grype/pkg"' "$A25_PROVIDER" >/dev/null || {
  echo "A25 source guard failed: expected grype/pkg provider import missing" >&2
  exit 98
}

grep -F 'PackageSearchNames(grypePkg.Package) []string' "$A25_PROVIDER" >/dev/null || {
  echo "A25 source guard failed: expected PackageSearchNames provider method missing" >&2
  exit 98
}

sed -i '\#grypePkg "github.com/anchore/grype/grype/pkg"#d' "$A25_PROVIDER"
sed -i '\#PackageSearchNames(grypePkg.Package) \[\]string#d' "$A25_PROVIDER"
gofmt -w "$A25_PROVIDER"

if grep -n -F '"github.com/anchore/grype/grype/pkg"' "$A25_PROVIDER" >/tmp/a25-provider-blocked.txt 2>/dev/null; then
  cat /tmp/a25-provider-blocked.txt >&2
  echo "A25 reduction failed: provider.go still imports grype/pkg" >&2
  exit 99
fi

if grep -n -F 'PackageSearchNames(grypePkg.Package)' "$A25_PROVIDER" >/tmp/a25-provider-method.txt 2>/dev/null; then
  cat /tmp/a25-provider-method.txt >&2
  echo "A25 reduction failed: broad PackageSearchNames method still present" >&2
  exit 99
fi

grep -F 'FindVulnerabilities(criteria ...Criteria) ([]Vulnerability, error)' "$A25_PROVIDER" >/dev/null || {
  echo "A25 contract guard failed: FindVulnerabilities missing" >&2
  exit 99
}

grep -F 'MetadataProvider' "$A25_PROVIDER" >/dev/null || {
  echo "A25 contract guard failed: MetadataProvider missing" >&2
  exit 99
}

grep -F 'io.Closer' "$A25_PROVIDER" >/dev/null || {
  echo "A25 contract guard failed: io.Closer missing" >&2
  exit 99
}

printf '%s\n' '{"status":"pass","reduction":"a25-vulnerability-provider","removed":"PackageSearchNames(grypePkg.Package)","policyGate":"unchanged"}'

# A28: A27 compiled-path evidence proves the controlled offline-v6 reader only
# carries qualifier.Qualifier values through vulnerability data. The matcher/full
# Grype path owns Satisfied(pkg.Package); that path is outside this controlled
# wrapper. Reduce only the temporary controlled-build qualifier contract.
A28_QUALIFIER="/tmp/grype/grype/pkg/qualifier/qualifier.go"

if [ ! -f "$A28_QUALIFIER" ]; then
  echo "A28 required qualifier source missing: $A28_QUALIFIER" >&2
  exit 98
fi

grep -F '"github.com/anchore/grype/grype/pkg"' "$A28_QUALIFIER" >/dev/null || {
  echo "A28 source guard failed: expected grype/pkg qualifier import missing" >&2
  exit 98
}

grep -F 'Satisfied(p pkg.Package) (bool, error)' "$A28_QUALIFIER" >/dev/null || {
  echo "A28 source guard failed: expected Qualifier.Satisfied signature missing" >&2
  exit 98
}

cat > "$A28_QUALIFIER" <<'A28QUALIFIER'
package qualifier

// Qualifier is intentionally data-only in the controlled offline-v6 reader.
//
// Upstream Grype's full matcher path defines this contract with
// Satisfied(pkg.Package). The controlled SentryCode Grype wrapper does not
// compile or execute that matcher path; A27 evidence proves DB/vulnerability
// code only carries qualifier values on vulnerability records.
//
// Keeping this as a marker interface removes the otherwise unused dependency
// on grype/pkg, which would pull broad Syft source/cataloger functionality into
// the controlled scanner binary.
type Qualifier interface{}
A28QUALIFIER

gofmt -w "$A28_QUALIFIER"

if grep -n -F '"github.com/anchore/grype/grype/pkg"' "$A28_QUALIFIER" >/tmp/a28-qualifier-import.txt 2>/dev/null; then
  cat /tmp/a28-qualifier-import.txt >&2
  echo "A28 reduction failed: qualifier.go still imports grype/pkg" >&2
  exit 99
fi

if grep -n -F 'Satisfied(p pkg.Package)' "$A28_QUALIFIER" >/tmp/a28-qualifier-method.txt 2>/dev/null; then
  cat /tmp/a28-qualifier-method.txt >&2
  echo "A28 reduction failed: broad Qualifier.Satisfied method still present" >&2
  exit 99
fi

grep -F 'type Qualifier interface{}' "$A28_QUALIFIER" >/dev/null || {
  echo "A28 contract guard failed: data-only Qualifier marker missing" >&2
  exit 99
}

printf '%s\n' '{"status":"pass","reduction":"a28-qualifier-interface","mode":"data-only","policyGate":"unchanged"}'

printf '%s\n' '{"status":"pass","reduction":"a18-fix6-probe-native","policyGate":"unchanged"}'

# A32: remove A31-proven unused v5 Namespace Resolver() contract/state.
A32_NS_ROOT="/tmp/grype/grype/db/v5/namespace"
A32_NS="$A32_NS_ROOT/namespace.go"
A32_CPE="$A32_NS_ROOT/cpe/namespace.go"
A32_DISTRO="$A32_NS_ROOT/distro/namespace.go"
A32_LANGUAGE="$A32_NS_ROOT/language/namespace.go"

for A32_FILE in "$A32_NS" "$A32_CPE" "$A32_DISTRO" "$A32_LANGUAGE"; do
  test -f "$A32_FILE" || { echo "A32 missing source: $A32_FILE" >&2; exit 1; }
done

# Guard the exact upstream/selected resolver contract before mutation.
grep -Fq '"github.com/anchore/grype/grype/db/v5/pkg/resolver"' "$A32_NS" || {
  echo "A32 namespace resolver import guard failed" >&2; exit 1;
}
grep -Fq 'Resolver() resolver.Resolver' "$A32_NS" || {
  echo "A32 namespace Resolver() interface guard failed" >&2; exit 1;
}

grep -Fq '"github.com/anchore/grype/grype/db/v5/pkg/resolver"' "$A32_CPE" || {
  echo "A32 cpe resolver import guard failed" >&2; exit 1;
}
grep -Fq '"github.com/anchore/grype/grype/db/v5/pkg/resolver/stock"' "$A32_CPE" || {
  echo "A32 cpe stock resolver import guard failed" >&2; exit 1;
}
grep -Fq 'resolver resolver.Resolver' "$A32_CPE" || {
  echo "A32 cpe resolver field guard failed" >&2; exit 1;
}
grep -Fq 'resolver: &stock.Resolver{},' "$A32_CPE" || {
  echo "A32 cpe resolver initializer guard failed" >&2; exit 1;
}
grep -Fq 'func (n *Namespace) Resolver() resolver.Resolver {' "$A32_CPE" || {
  echo "A32 cpe Resolver() method guard failed" >&2; exit 1;
}

grep -Fq '"github.com/anchore/grype/grype/db/v5/pkg/resolver"' "$A32_DISTRO" || {
  echo "A32 distro resolver import guard failed" >&2; exit 1;
}
grep -Fq '"github.com/anchore/grype/grype/db/v5/pkg/resolver/stock"' "$A32_DISTRO" || {
  echo "A32 distro stock resolver import guard failed" >&2; exit 1;
}
grep -Fq 'resolver   resolver.Resolver' "$A32_DISTRO" || {
  echo "A32 distro resolver field guard failed" >&2; exit 1;
}
grep -Fq 'resolver:   &stock.Resolver{},' "$A32_DISTRO" || {
  echo "A32 distro resolver initializer guard failed" >&2; exit 1;
}
grep -Fq 'func (n *Namespace) Resolver() resolver.Resolver {' "$A32_DISTRO" || {
  echo "A32 distro Resolver() method guard failed" >&2; exit 1;
}

grep -Fq '"github.com/anchore/grype/grype/db/v5/pkg/resolver"' "$A32_LANGUAGE" || {
  echo "A32 language resolver import guard failed" >&2; exit 1;
}
grep -Fq 'resolver    resolver.Resolver' "$A32_LANGUAGE" || {
  echo "A32 language resolver field guard failed" >&2; exit 1;
}
grep -Fq 'r, _ := resolver.FromLanguage(language)' "$A32_LANGUAGE" || {
  echo "A32 language resolver initializer guard failed" >&2; exit 1;
}
grep -Fq 'resolver:    r,' "$A32_LANGUAGE" || {
  echo "A32 language resolver assignment guard failed" >&2; exit 1;
}
grep -Fq 'func (n *Namespace) Resolver() resolver.Resolver {' "$A32_LANGUAGE" || {
  echo "A32 language Resolver() method guard failed" >&2; exit 1;
}

python3 - "$A32_NS" "$A32_CPE" "$A32_DISTRO" "$A32_LANGUAGE" <<'PY'
from pathlib import Path
import sys

ns, cpe, distro, language = map(Path, sys.argv[1:])

def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"A32 {label}: expected 1 occurrence, found {count}")
    return text.replace(old, new, 1)

# Root Namespace interface: remove only resolver import + Resolver() requirement.
t = ns.read_text()
t = replace_once(
    t,
    'import (\n\t"github.com/anchore/grype/grype/db/v5/pkg/resolver"\n)\n\n',
    '',
    'namespace resolver import',
)
t = replace_once(
    t,
    '\tResolver() resolver.Resolver\n',
    '',
    'namespace Resolver() method',
)
ns.write_text(t)

# CPE namespace: remove only resolver dependencies/state/method.
t = cpe.read_text()
t = replace_once(
    t,
    '\n\t"github.com/anchore/grype/grype/db/v5/pkg/resolver"\n\t"github.com/anchore/grype/grype/db/v5/pkg/resolver/stock"',
    '',
    'cpe resolver imports',
)
t = replace_once(
    t,
    '\tresolver resolver.Resolver\n',
    '',
    'cpe resolver field',
)
t = replace_once(
    t,
    '\t\tresolver: &stock.Resolver{},\n',
    '',
    'cpe resolver initializer',
)
t = replace_once(
    t,
    'func (n *Namespace) Resolver() resolver.Resolver {\n\treturn n.resolver\n}\n\n',
    '',
    'cpe Resolver() method',
)
cpe.write_text(t)

# Distro namespace: preserve provider/type/version; remove resolver only.
t = distro.read_text()
t = replace_once(
    t,
    '\n\t"github.com/anchore/grype/grype/db/v5/pkg/resolver"\n\t"github.com/anchore/grype/grype/db/v5/pkg/resolver/stock"',
    '',
    'distro resolver imports',
)
t = replace_once(
    t,
    '\tresolver   resolver.Resolver\n',
    '',
    'distro resolver field',
)
t = replace_once(
    t,
    '\t\tresolver:   &stock.Resolver{},\n',
    '',
    'distro resolver initializer',
)
t = replace_once(
    t,
    'func (n *Namespace) Resolver() resolver.Resolver {\n\treturn n.resolver\n}\n\n',
    '',
    'distro Resolver() method',
)
distro.write_text(t)

# Language namespace: preserve provider/language/packageType; remove resolver only.
t = language.read_text()
t = replace_once(
    t,
    '\n\t"github.com/anchore/grype/grype/db/v5/pkg/resolver"',
    '',
    'language resolver import',
)
t = replace_once(
    t,
    '\tresolver    resolver.Resolver\n',
    '',
    'language resolver field',
)
t = replace_once(
    t,
    '\tr, _ := resolver.FromLanguage(language)\n\n',
    '',
    'language resolver initialization',
)
t = replace_once(
    t,
    '\t\tresolver:    r,\n',
    '',
    'language resolver assignment',
)
t = replace_once(
    t,
    'func (n *Namespace) Resolver() resolver.Resolver {\n\treturn n.resolver\n}\n\n',
    '',
    'language Resolver() method',
)
language.write_text(t)
PY

# Post-mutation guards: no resolver dependency remains in the four selected namespace files.
if grep -n -E 'db/v5/pkg/resolver|resolver\.Resolver|Resolver\(\)' \
  "$A32_NS" "$A32_CPE" "$A32_DISTRO" "$A32_LANGUAGE"; then
  echo "A32 post-mutation resolver-removal guard failed" >&2
  exit 1
fi

# Required search-facing behavior must remain.
grep -Fq 'Provider() string' "$A32_NS" || { echo "A32 Namespace Provider() lost" >&2; exit 1; }
grep -Fq 'String() string' "$A32_NS" || { echo "A32 Namespace String() lost" >&2; exit 1; }

grep -Fq 'func (n *Namespace) DistroType() distro.Type {' "$A32_DISTRO" || {
  echo "A32 distro DistroType() lost" >&2; exit 1;
}
grep -Fq 'func (n *Namespace) Version() string {' "$A32_DISTRO" || {
  echo "A32 distro Version() lost" >&2; exit 1;
}
grep -Fq 'func (n *Namespace) Language() syftPkg.Language {' "$A32_LANGUAGE" || {
  echo "A32 language Language() lost" >&2; exit 1;
}
grep -Fq 'func (n *Namespace) PackageType() syftPkg.Type {' "$A32_LANGUAGE" || {
  echo "A32 language PackageType() lost" >&2; exit 1;
}

gofmt -w "$A32_NS" "$A32_CPE" "$A32_DISTRO" "$A32_LANGUAGE"

printf '%s\n' \
  '{"status":"pass","reduction":"a32-v5-namespace-resolver","removed":"unused Resolver() contract/state","policyGate":"unchanged"}'

# A33: final dependency graph after all controlled-source reductions, immediately before compile.
go list -deps -f '{{.ImportPath}}|{{join .Imports ","}}' . \
  > /work/a33-final-prebuild-dep-edges.txt

go list -deps -f '{{.ImportPath}}' . \
  > /work/a33-final-prebuild-deps.txt

grep -E \
  '^(quilons\.local/controlled-grype|github\.com/anchore/grype/grype/(db/v6|search|db/v5/namespace|db/v5/pkg/resolver|pkg|version|vulnerability)|github\.com/anchore/syft/syft/pkg)(\||$)' \
  /work/a33-final-prebuild-dep-edges.txt \
  > /work/a33-final-prebuild-key-edges.txt || true

printf '%s\n' \
  '{"status":"pass","diagnostic":"a33-final-prebuild-graph","position":"immediately-before-controlled-go-build"}'

printf '%s\n' \
  '{"status":"pass","hardening":"a34-go-network-retry","maxAttempts":5,"backoffSeconds":[5,10,15,20],"jsonAtomic":true,"policyGate":"unchanged"}'
retry_go env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /work/quilons-grype .
go version -m /work/quilons-grype > /work/go-version-m.txt
go list -deps . | sort > /work/go-list-deps.txt
go list -deps -f '{{.ImportPath}}|{{join .Imports ","}}' . | sort > /work/go-dep-edges.txt

# A24: preserve exact source contracts for the sole remaining contamination root.
cp /tmp/grype/grype/vulnerability/provider.go /work/a24-vulnerability-provider.go
cp /tmp/grype/grype/vulnerability/vulnerability.go /work/a24-vulnerability-vulnerability.go
cp /tmp/grype/grype/vulnerability/metadata.go /work/a24-vulnerability-metadata.go
cp /tmp/grype/grype/vulnerability/advisory.go /work/a24-vulnerability-advisory.go
cp /tmp/grype/grype/vulnerability/fix.go /work/a24-vulnerability-fix.go
cp /tmp/grype/grype/vulnerability/severity.go /work/a24-vulnerability-severity.go

: > /work/a24-db-v6-vulnerability-importers.txt
for A24_FILE in /tmp/grype/grype/db/v6/*.go; do
  case "$A24_FILE" in
    *_test.go) continue ;;
  esac
  if grep -F '"github.com/anchore/grype/grype/vulnerability"' "$A24_FILE" >/dev/null 2>&1; then
    printf '%s\n' "===== $A24_FILE =====" >> /work/a24-db-v6-vulnerability-importers.txt
    cat "$A24_FILE" >> /work/a24-db-v6-vulnerability-importers.txt
    printf '\n' >> /work/a24-db-v6-vulnerability-importers.txt
  fi
done

grep -R -n -E --include='*.go' --exclude='*_test.go' \
  'grypePkg\.|pkg\.' /tmp/grype/grype/vulnerability \
  > /work/a24-vulnerability-pkg-usages.txt 2>/dev/null || true

# A26: exact source evidence for the post-A25 sole remaining broad edge.
# A27: determine whether the compiled controlled path calls Qualifier.Satisfied.
grep -R -n -E --include='*.go' --exclude='*_test.go' \
  '\.Satisfied\(|Satisfied\(.*pkg\.Package|qualifier\.Qualifier|PackageQualifiers' \
  /tmp/grype/grype > /work/a27-qualifier-usage-all.txt 2>/dev/null || true

: > /work/a27-qualifier-usage-compiled-packages.txt
while IFS= read -r A27_IMPORT; do
  case "$A27_IMPORT" in
    github.com/anchore/grype/*)
      A27_DIR="$(go list -f '{{.Dir}}' "$A27_IMPORT" 2>/dev/null || true)"
      if [ -n "$A27_DIR" ] && [ -d "$A27_DIR" ]; then
        A27_MATCHES="$(grep -R -n -E --include='*.go' --exclude='*_test.go' \
          '\.Satisfied\(|Satisfied\(.*pkg\.Package|qualifier\.Qualifier|PackageQualifiers' \
          "$A27_DIR" 2>/dev/null || true)"
        if [ -n "$A27_MATCHES" ]; then
          printf '%s\n' "===== $A27_IMPORT =====" >> /work/a27-qualifier-usage-compiled-packages.txt
          printf '%s\n' "$A27_MATCHES" >> /work/a27-qualifier-usage-compiled-packages.txt
        fi
      fi
      ;;
  esac
done < /work/go-list-deps.txt

grep -R -n -E --include='*.go' --exclude='*_test.go' \
  'type .*Qualifier|func .*Satisfied\(' \
  /tmp/grype/grype/pkg/qualifier > /work/a27-qualifier-implementations.txt 2>/dev/null || true

grep -R -n -E --include='*.go' --exclude='*_test.go' \
  'PackageQualifiers|qualifier\.Qualifier' \
  /tmp/grype/grype/db/v6 /tmp/grype/grype/vulnerability \
  > /work/a27-db-vulnerability-qualifier-usages.txt 2>/dev/null || true

# A31: exact source evidence for v5 namespace subpackages retained by the v6 search-query adapter.
for A31_IMPORT in \
  github.com/anchore/grype/grype/db/v5/namespace/cpe \
  github.com/anchore/grype/grype/db/v5/namespace/distro \
  github.com/anchore/grype/grype/db/v5/namespace/language
do
  A31_SAFE="$(printf '%s' "$A31_IMPORT" | sed 's#github.com/anchore/grype/grype/db/v5/namespace/##')"
  go list -f '{{.Dir}}|{{join .GoFiles ","}}|{{join .CgoFiles ","}}|{{join .IgnoredGoFiles ","}}|{{join .Imports ","}}' \
    "$A31_IMPORT" > "/work/a31-${A31_SAFE}-selected.txt"

  A31_DIR="$(go list -f '{{.Dir}}' "$A31_IMPORT")"

  grep -R -n -E --include='*.go' --exclude='*_test.go' \
    'Resolver\(|resolver\.|db/v5/pkg/resolver|DistroType\(|Version\(|Language\(|Provider\(|String\(|FromComponents\(' \
    "$A31_DIR" > "/work/a31-${A31_SAFE}-contract-usages.txt" 2>/dev/null || true

  : > "/work/a31-${A31_SAFE}-production-source.txt"
  for A31_FILE in "$A31_DIR"/*.go; do
    case "$A31_FILE" in
      *_test.go) continue ;;
    esac
    printf '%s\n' "===== $A31_FILE =====" >> "/work/a31-${A31_SAFE}-production-source.txt"
    cat "$A31_FILE" >> "/work/a31-${A31_SAFE}-production-source.txt"
    printf '\n' >> "/work/a31-${A31_SAFE}-production-source.txt"
  done
done

grep -R -n -E --include='*.go' --exclude='*_test.go' \
  '\.Resolver\(\)|Resolver\(\) resolver\.Resolver|resolver\.Resolver' \
  /tmp/grype/grype/db/v5/namespace \
  /tmp/grype/grype/search \
  /tmp/grype/grype/db/v6 \
  > /work/a31-resolver-call-sites.txt 2>/dev/null || true

# A30: prove exact db/v6 usage of grype/search before any search-package reduction.
grep -R -n -E --include='*.go' --exclude='*_test.go' \
  '"github\.com/anchore/grype/grype/search"|search\.[A-Za-z_][A-Za-z0-9_]*' \
  /tmp/grype/grype/db/v6 > /work/a30-dbv6-search-usages.txt 2>/dev/null || true

grep -R -n -E --include='*.go' --exclude='*_test.go' \
  'ByDistro\(|ByExactDistro\(|DistroCriteria|ByEcosystem\(|EcosystemCriteria|namespace\.FromString' \
  /tmp/grype/grype/db/v6 > /work/a30-dbv6-legacy-search-symbols.txt 2>/dev/null || true

grep -R -n -E --include='*.go' --exclude='*_test.go' \
  'ByCPE\(|ByPackageName\(|ByVersion\(|ByFixedVersion\(|ForUnaffected\(|ByConstraintFunc\(|ValidateCriteria\(|CriteriaIterator\(' \
  /tmp/grype/grype/db/v6 > /work/a30-dbv6-narrow-search-symbols.txt 2>/dev/null || true

: > /work/a30-dbv6-search-caller-source.txt
for A30_FILE in /tmp/grype/grype/db/v6/*.go; do
  case "$A30_FILE" in
    *_test.go) continue ;;
  esac
  if grep -q -E '"github\.com/anchore/grype/grype/search"|search\.' "$A30_FILE"; then
    printf '%s\n' "===== $A30_FILE =====" >> /work/a30-dbv6-search-caller-source.txt
    cat "$A30_FILE" >> /work/a30-dbv6-search-caller-source.txt
    printf '\n' >> /work/a30-dbv6-search-caller-source.txt
  fi
done

printf '%s\n' \
  /tmp/grype/grype/search/distro.go \
  /tmp/grype/grype/search/ecosystem.go \
  > /work/a30-legacy-search-candidates.txt

# A29: exact source evidence for the post-A28 residual chain:
# db/v6 -> search -> db/v5/namespace -> db/v5/pkg/resolver -> grype/pkg
for A29_IMPORT in \
  github.com/anchore/grype/grype/search \
  github.com/anchore/grype/grype/db/v5/namespace \
  github.com/anchore/grype/grype/db/v5/pkg/resolver
do
  A29_SAFE="$(printf '%s' "$A29_IMPORT" | sed 's#github.com/anchore/grype/grype/##; s#/#-#g')"
  go list -json "$A29_IMPORT" > "/work/a29-${A29_SAFE}-package.json"
  go list -f '{{.Dir}}|{{join .GoFiles ","}}|{{join .CgoFiles ","}}|{{join .IgnoredGoFiles ","}}|{{join .Imports ","}}' \
    "$A29_IMPORT" > "/work/a29-${A29_SAFE}-selected.txt"

  A29_DIR="$(go list -f '{{.Dir}}' "$A29_IMPORT")"

  find "$A29_DIR" -maxdepth 1 -type f -name '*.go' -print | sort \
    > "/work/a29-${A29_SAFE}-all-go-files.txt"

  grep -R -n -E --include='*.go' --exclude='*_test.go' \
    'github\.com/anchore/grype/grype/(search|db/v5/namespace|db/v5/pkg/resolver|pkg)|pkg\.' \
    "$A29_DIR" > "/work/a29-${A29_SAFE}-residual-usages.txt" 2>/dev/null || true

  : > "/work/a29-${A29_SAFE}-production-source.txt"
  for A29_FILE in "$A29_DIR"/*.go; do
    case "$A29_FILE" in
      *_test.go) continue ;;
    esac
    printf '%s\n' "===== $A29_FILE =====" >> "/work/a29-${A29_SAFE}-production-source.txt"
    cat "$A29_FILE" >> "/work/a29-${A29_SAFE}-production-source.txt"
    printf '\n' >> "/work/a29-${A29_SAFE}-production-source.txt"
  done
done

grep -E \
  '^(github.com/anchore/grype/grype/(db/v6|search|db/v5/namespace|db/v5/pkg/resolver))\|' \
  /work/go-dep-edges.txt > /work/a29-residual-chain-edges.txt || true

go list -json github.com/anchore/grype/grype/pkg/qualifier > /work/a26-qualifier-package.json
go list -f '{{.Dir}}|{{join .GoFiles ","}}|{{join .CgoFiles ","}}|{{join .IgnoredGoFiles ","}}|{{join .Imports ","}}' \
  github.com/anchore/grype/grype/pkg/qualifier > /work/a26-qualifier-selected.txt

A26_QUALIFIER_DIR="$(go list -f '{{.Dir}}' github.com/anchore/grype/grype/pkg/qualifier)"

find "$A26_QUALIFIER_DIR" -maxdepth 1 -type f -name '*.go' -print | sort \
  > /work/a26-qualifier-all-go-files.txt

grep -R -n -E --include='*.go' --exclude='*_test.go' \
  'github\.com/anchore/grype/grype/pkg|grypePkg\.' \
  "$A26_QUALIFIER_DIR" > /work/a26-qualifier-pkg-usages.txt 2>/dev/null || true

: > /work/a26-qualifier-production-source.txt
for A26_FILE in "$A26_QUALIFIER_DIR"/*.go; do
  case "$A26_FILE" in
    *_test.go) continue ;;
  esac
  printf '%s\n' "===== $A26_FILE =====" >> /work/a26-qualifier-production-source.txt
  cat "$A26_FILE" >> /work/a26-qualifier-production-source.txt
  printf '\n' >> /work/a26-qualifier-production-source.txt
done

go list -json github.com/anchore/grype/grype/db/v6 > /work/a23-db-v6-package.json
go list -json github.com/anchore/grype/grype/vulnerability > /work/a23-vulnerability-package.json

go list -f '{{.Dir}}|{{join .GoFiles ","}}|{{join .CgoFiles ","}}|{{join .IgnoredGoFiles ","}}|{{join .Imports ","}}' github.com/anchore/grype/grype/db/v6 > /work/a23-db-v6-selected.txt
go list -f '{{.Dir}}|{{join .GoFiles ","}}|{{join .CgoFiles ","}}|{{join .IgnoredGoFiles ","}}|{{join .Imports ","}}' github.com/anchore/grype/grype/vulnerability > /work/a23-vulnerability-selected.txt

A23_DB_DIR="$(go list -f '{{.Dir}}' github.com/anchore/grype/grype/db/v6)"
A23_VULN_DIR="$(go list -f '{{.Dir}}' github.com/anchore/grype/grype/vulnerability)"

find "$A23_DB_DIR" -maxdepth 1 -type f -name '*.go' -print | sort > /work/a23-db-v6-all-go-files.txt
find "$A23_VULN_DIR" -maxdepth 1 -type f -name '*.go' -print | sort > /work/a23-vulnerability-all-go-files.txt

grep -R -n -E --include='*.go' --exclude='*_test.go' \
  'github\.com/anchore/grype/grype/(vulnerability|pkg)|github\.com/anchore/syft' \
  "$A23_DB_DIR" > /work/a23-db-v6-relevant-imports.txt 2>/dev/null || true

grep -R -n -E --include='*.go' --exclude='*_test.go' \
  'github\.com/anchore/grype/grype/pkg|github\.com/anchore/syft' \
  "$A23_VULN_DIR" > /work/a23-vulnerability-relevant-imports.txt 2>/dev/null || true

go list -json github.com/anchore/grype/grype/db/v6/name > /work/a21-name-package.json
go list -json github.com/anchore/grype/grype/version > /work/a21-version-package.json

go list -f '{{.Dir}}|{{join .GoFiles ","}}|{{join .CgoFiles ","}}|{{join .IgnoredGoFiles ","}}|{{join .Imports ","}}' github.com/anchore/grype/grype/db/v6/name > /work/a21-name-selected.txt
go list -f '{{.Dir}}|{{join .GoFiles ","}}|{{join .CgoFiles ","}}|{{join .IgnoredGoFiles ","}}|{{join .Imports ","}}' github.com/anchore/grype/grype/version > /work/a21-version-selected.txt

NAME_SELECTED_DIR="$(go list -f '{{.Dir}}' github.com/anchore/grype/grype/db/v6/name)"
VERSION_SELECTED_DIR="$(go list -f '{{.Dir}}' github.com/anchore/grype/grype/version)"

printf '%s\n' "$NAME_SELECTED_DIR" > /work/a21-name-dir.txt
printf '%s\n' "$VERSION_SELECTED_DIR" > /work/a21-version-dir.txt

find "$NAME_SELECTED_DIR" -maxdepth 1 -type f -name '*.go' -print | sort > /work/a21-name-all-go-files.txt
find "$VERSION_SELECTED_DIR" -maxdepth 1 -type f -name '*.go' -print | sort > /work/a21-version-all-go-files.txt

grep -R -n -E --include='*.go' --exclude='*_test.go' 'github\.com/anchore/grype/grype/pkg|github\.com/anchore/syft' "$NAME_SELECTED_DIR" > /work/a21-name-relevant-imports.txt 2>/dev/null || true
grep -R -n -E --include='*.go' --exclude='*_test.go' 'github\.com/masahiro331/go-mvn-version|github\.com/hashicorp/(go-multierror|errwrap)' "$VERSION_SELECTED_DIR" > /work/a21-version-relevant-imports.txt 2>/dev/null || true

/work/quilons-grype --version > /work/version.txt
cat /work/version.txt
'@

    [System.IO.File]::WriteAllText((Join-Path $Work 'probe.sh'),$Probe,(New-Object System.Text.UTF8Encoding($false)))

    $MountArg = "type=bind,src=$Work,dst=/work"
    $Out = Join-Path $Work 'docker.stdout.txt'
    $Err = Join-Path $Work 'docker.stderr.txt'

    $P = Start-Process -FilePath 'docker.exe' `
        -ArgumentList @(
            'run','--rm',
            '--mount',('"' + $MountArg + '"'),
            '-e','GOTOOLCHAIN=local',
            '-e','GOSUMDB=sum.golang.org',
            $GoImage,
            '/bin/sh','/work/probe.sh'
        ) `
        -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $Out `
        -RedirectStandardError $Err

    Get-Content -LiteralPath $Out -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
    Get-Content -LiteralPath $Err -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }

    if ($P.ExitCode -ne 0) { Fail "Controlled Grype build failed with exit $($P.ExitCode)." }

    $PolicyOut = Join-Path $Work 'policy.stdout.txt'
    $PolicyErr = Join-Path $Work 'policy.stderr.txt'
    $P = Start-Process -FilePath 'node.exe' `
        -ArgumentList @((Join-Path $Work 'verify-policy-modules.mjs'),(Join-Path $Work 'go-version-m.txt')) `
        -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $PolicyOut `
        -RedirectStandardError $PolicyErr

    Get-Content -LiteralPath $PolicyOut -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
    Get-Content -LiteralPath $PolicyErr -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }

    if ($P.ExitCode -ne 0) { Fail 'Controlled Grype binary failed unchanged nine-module gate.' }

    # A35: retain authoritative evidence from a successful controlled build before $Work is deleted.
    $EvidenceRoot = Join-Path $Base 'evidence\slice2c-a35-l01'
    New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null

    $EvidenceFiles = @(
        'go-version-m.txt',
        'go-list-deps.txt',
        'go-dep-edges.txt',
        'a33-final-prebuild-dep-edges.txt',
        'a33-final-prebuild-deps.txt',
        'a33-final-prebuild-key-edges.txt',
        'policy.stdout.txt',
        'policy.stderr.txt'
    )

    foreach ($EvidenceName in $EvidenceFiles) {
        $EvidenceSource = Join-Path $Work $EvidenceName
        if (-not (Test-Path -LiteralPath $EvidenceSource -PathType Leaf)) {
            Fail ("A35 required success evidence missing: {0}" -f $EvidenceName)
        }
        Copy-Item -LiteralPath $EvidenceSource -Destination (Join-Path $EvidenceRoot $EvidenceName) -Force
    }

    $EvidenceManifest = Join-Path $EvidenceRoot 'manifest.sha256.txt'
    $EvidenceLines = foreach ($EvidenceName in $EvidenceFiles) {
        $EvidencePath = Join-Path $EvidenceRoot $EvidenceName
        $EvidenceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $EvidencePath).Hash.ToLowerInvariant()
        "{0}  {1}" -f $EvidenceHash, $EvidenceName
    }
    [System.IO.File]::WriteAllLines(
        $EvidenceManifest,
        $EvidenceLines,
        (New-Object System.Text.UTF8Encoding($false))
    )

    Write-Host '{"status":"pass","retention":"a35-success-evidence-retention","policyGate":"unchanged"}'
    Write-Host ("A35 EVIDENCE DIRECTORY: {0}" -f $EvidenceRoot)
    Get-Content -LiteralPath $EvidenceManifest | ForEach-Object { Write-Host $_ }

    $Context = Join-Path $Work 'image'
    New-Item -ItemType Directory -Force -Path $Context | Out-Null
    Copy-Item -LiteralPath (Join-Path $Work 'quilons-grype') -Destination (Join-Path $Context 'quilons-grype')
    Copy-Item -LiteralPath (Join-Path $Work 'Dockerfile') -Destination (Join-Path $Context 'Dockerfile')

    & docker.exe build --pull=false --network=none -t $ImageTag $Context
    if ($LASTEXITCODE -ne 0) { Fail 'Controlled Grype scratch image build failed.' }

    $VersionOut = (& docker.exe run --rm --network none --read-only $ImageTag --version 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { Fail 'Controlled Grype scratch image version probe failed.' }
    Write-Host $VersionOut.TrimEnd()

    if ($VersionOut -notmatch 'quilons-controlled-grype 0\.120\.0-quilons\.1') { Fail 'Controlled Grype version identity mismatch.' }
    if ($VersionOut -notmatch 'upstream: grype 0\.120\.0') { Fail 'Controlled Grype upstream identity mismatch.' }
    if ($VersionOut -notmatch 'mode: offline-local-v6') { Fail 'Controlled Grype offline mode identity mismatch.' }

    Write-Host 'Policy-target modules : 0'
    Write-Host 'Runtime network       : none'
    Write-Host 'Runtime root filesystem: read-only'
    Write-Host 'CONTROLLED GRYPE BUILD FOUNDATION: PASS'
    $BuildSucceeded = $true
}
finally {
    if (Test-Path -LiteralPath $Work) {
        if ($BuildSucceeded) {
            $LongWork = '\\?\' + $Work
            try {
                Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d','/s','/c',"rd /s /q `"$LongWork`"") -Wait -PassThru -NoNewWindow | Out-Null
            } catch {
            }
        }
        else {
            Write-Host ("PRESERVED FAILED WORK DIRECTORY: {0}" -f $Work)
        }
    }
}
