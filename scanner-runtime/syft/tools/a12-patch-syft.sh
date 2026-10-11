#!/bin/sh
set -eu

SYFT_ROOT="${1:-/tmp/syft}"

GOUPX="$SYFT_ROOT/syft/pkg/cataloger/golang/upx.go"
test -f "$GOUPX"
test "$(grep -F -c 'intFile "github.com/anchore/syft/internal/file"' "$GOUPX" || true)" = "1"
test "$(grep -F -c 'intFile.ReaderSize(r)' "$GOUPX" || true)" = "1"

sed -i '/intFile "github.com\/anchore\/syft\/internal\/file"/d' "$GOUPX"
sed -i 's/intFile\.MB/(1024 * 1024)/g' "$GOUPX"
sed -i 's/intFile\.KB/1024/g' "$GOUPX"
sed -i 's/intFile\.ReaderSize(r)/quilonsReaderSize(r)/g' "$GOUPX"

cat > "$SYFT_ROOT/syft/pkg/cataloger/golang/quilons_reader_size.go" <<'EOF_GO'
package golang

import (
	"io"
	"os"
)

type quilonsSizer interface {
	Size() int64
}

func quilonsReaderSize(r io.ReaderAt) (int64, bool) {
	if r == nil {
		return 0, false
	}
	verify := func(n int64) (int64, bool) {
		if n <= 0 {
			return 0, false
		}
		var last [1]byte
		if count, _ := r.ReadAt(last[:], n-1); count != len(last) {
			return 0, false
		}
		return n, true
	}
	if s, ok := r.(quilonsSizer); ok {
		if n, ok := verify(s.Size()); ok {
			return n, true
		}
	}
	if f, ok := r.(*os.File); ok {
		if info, err := f.Stat(); err == nil {
			if n, ok := verify(info.Size()); ok {
				return n, true
			}
		}
	}
	if seeker, ok := r.(io.Seeker); ok {
		current, err := seeker.Seek(0, io.SeekCurrent)
		if err != nil {
			return 0, false
		}
		end, err := seeker.Seek(0, io.SeekEnd)
		if _, restoreErr := seeker.Seek(current, io.SeekStart); err != nil || restoreErr != nil {
			return 0, false
		}
		return verify(end)
	}
	return 0, false
}
EOF_GO

mkdir -p "$SYFT_ROOT/internal/quilonsfile"
cat > "$SYFT_ROOT/internal/quilonsfile/helper.go" <<'EOF_JAVA'
package quilonsfile

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	syftFile "github.com/anchore/syft/syft/file"
)

const (
	KB = 1024
	MB = 1024 * KB
)

type sizer interface {
	Size() int64
}

func ReaderSize(r io.ReaderAt) (int64, bool) {
	if r == nil {
		return 0, false
	}
	verify := func(n int64) (int64, bool) {
		if n <= 0 {
			return 0, false
		}
		var last [1]byte
		if count, _ := r.ReadAt(last[:], n-1); count != len(last) {
			return 0, false
		}
		return n, true
	}
	if s, ok := r.(sizer); ok {
		if n, ok := verify(s.Size()); ok {
			return n, true
		}
	}
	if f, ok := r.(*os.File); ok {
		if info, err := f.Stat(); err == nil {
			if n, ok := verify(info.Size()); ok {
				return n, true
			}
		}
	}
	if seeker, ok := r.(io.Seeker); ok {
		current, err := seeker.Seek(0, io.SeekCurrent)
		if err != nil {
			return 0, false
		}
		end, err := seeker.Seek(0, io.SeekEnd)
		if _, restoreErr := seeker.Seek(current, io.SeekStart); err != nil || restoreErr != nil {
			return 0, false
		}
		return verify(end)
	}
	return 0, false
}

type Opener struct {
	path string
}

func (o Opener) Open() (io.ReadCloser, error) {
	return os.Open(o.path)
}

type ZipFileManifest map[string]os.FileInfo

func (z ZipFileManifest) GlobMatch(caseInsensitive bool, patterns ...string) []string {
	var out []string
	for name := range z {
		candidate := filepath.ToSlash(name)
		for _, pattern := range patterns {
			p := filepath.ToSlash(pattern)
			left, right := candidate, p
			if caseInsensitive {
				left, right = strings.ToLower(left), strings.ToLower(right)
			}
			ok, err := doublestar.Match(right, left)
			if err == nil && ok {
				out = append(out, name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func NewZipFileManifest(ctx context.Context, archivePath string) (ZipFileManifest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	result := ZipFileManifest{}
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result[filepath.ToSlash(f.Name)] = f.FileInfo()
	}
	return result, nil
}

func ContentsFromZip(ctx context.Context, archivePath string, paths ...string) (map[string]string, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	wanted := map[string]struct{}{}
	for _, p := range paths {
		wanted[filepath.ToSlash(p)] = struct{}{}
	}

	out := map[string]string{}
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := filepath.ToSlash(f.Name)
		if _, ok := wanted[name]; !ok {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, readErr := io.ReadAll(rc)
		closeErr := rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		out[name] = string(b)
	}
	return out, nil
}

func NewDigestsFromFile(ctx context.Context, closer io.ReadCloser, hashes []crypto.Hash) ([]syftFile.Digest, error) {
	defer closer.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	type hs struct {
		algorithm crypto.Hash
		hash      hash.Hash
	}
	var states []hs
	var writers []io.Writer

	for _, h := range hashes {
		if !h.Available() {
			return nil, fmt.Errorf("hash algorithm unavailable: %v", h)
		}
		x := h.New()
		states = append(states, hs{algorithm: h, hash: x})
		writers = append(writers, x)
	}

	if _, err := io.Copy(io.MultiWriter(writers...), closer); err != nil {
		return nil, err
	}

	result := make([]syftFile.Digest, 0, len(states))
	for _, item := range states {
		result = append(result, syftFile.Digest{
			Algorithm: item.algorithm.String(),
			Value:     fmt.Sprintf("%x", item.hash.Sum(nil)),
		})
	}
	return result, nil
}

func ExtractFromZipToUniqueTempFile(ctx context.Context, archivePath, dir string, paths ...string) (map[string]Opener, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	wanted := map[string]struct{}{}
	for _, p := range paths {
		wanted[filepath.ToSlash(p)] = struct{}{}
	}

	out := map[string]Opener{}
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := filepath.ToSlash(f.Name)
		if _, ok := wanted[name]; !ok {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		tmp, err := os.CreateTemp(dir, "quilons-syft-zip-*")
		if err != nil {
			rc.Close()
			return nil, err
		}
		tmpName := tmp.Name()

		_, copyErr := io.Copy(tmp, rc)
		closeReadErr := rc.Close()
		syncErr := tmp.Sync()
		closeWriteErr := tmp.Close()
		if copyErr != nil || closeReadErr != nil || syncErr != nil || closeWriteErr != nil {
			_ = os.Remove(tmpName)
			if copyErr != nil {
				return nil, copyErr
			}
			if closeReadErr != nil {
				return nil, closeReadErr
			}
			if syncErr != nil {
				return nil, syncErr
			}
			return nil, closeWriteErr
		}
		out[name] = Opener{path: tmpName}
	}

	return out, nil
}

func ExtractGlobsFromTarToUniqueTempFile(ctx context.Context, archivePath, dir string, globs ...string) (map[string]Opener, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var reader io.Reader = f
	lower := strings.ToLower(archivePath)

	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		reader = gz
	case strings.HasSuffix(lower, ".tar.bz"), strings.HasSuffix(lower, ".tar.bz2"), strings.HasSuffix(lower, ".tbz"), strings.HasSuffix(lower, ".tbz2"):
		reader = bzip2.NewReader(f)
	case strings.HasSuffix(lower, ".tar"):
	default:
		return nil, fmt.Errorf("unsupported tar compression in controlled Java cataloger: %s", archivePath)
	}

	tr := tar.NewReader(reader)
	out := map[string]Opener{}

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.FileInfo().IsDir() {
			continue
		}

		name := filepath.ToSlash(hdr.Name)
		match := false
		for _, pattern := range globs {
			ok, matchErr := doublestar.Match(filepath.ToSlash(pattern), name)
			if matchErr != nil {
				return nil, matchErr
			}
			if ok {
				match = true
				break
			}
		}
		if !match {
			continue
		}

		tmp, err := os.CreateTemp(dir, "quilons-syft-tar-*")
		if err != nil {
			return nil, err
		}
		tmpName := tmp.Name()
		if _, err := io.Copy(tmp, tr); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return nil, err
		}
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return nil, err
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmpName)
			return nil, err
		}
		out[name] = Opener{path: tmpName}
	}

	return out, nil
}
EOF_JAVA

find "$SYFT_ROOT/syft/pkg/cataloger/java" -type f -name '*.go' ! -name '*_test.go' -print0 | \
	xargs -0 sed -i 's#intFile "github.com/anchore/syft/internal/file"#intFile "github.com/anchore/syft/internal/quilonsfile"#g'

GRAAL="$SYFT_ROOT/syft/pkg/cataloger/java/graalvm_native_image_cataloger.go"
test -f "$GRAAL"
mv "$GRAAL" "$GRAAL.disabled"

ELFUTIL="$SYFT_ROOT/syft/internal/elfutil/elfutil.go"
test -f "$ELFUTIL"
test "$(grep -F -c 'intFile "github.com/anchore/syft/internal/file"' "$ELFUTIL" || true)" = "1"
test "$(grep -F -c 'const maxDeclaredSectionSize uint64 = 128 * intFile.MB' "$ELFUTIL" || true)" = "1"

sed -i '/intFile "github.com\/anchore\/syft\/internal\/file"/d' "$ELFUTIL"
sed -i 's/const maxDeclaredSectionSize uint64 = 128 \* intFile\.MB/const maxDeclaredSectionSize uint64 = 128 * 1024 * 1024/' "$ELFUTIL"

if find "$SYFT_ROOT/syft/pkg/cataloger/golang" "$SYFT_ROOT/syft/pkg/cataloger/java" "$SYFT_ROOT/syft/internal/elfutil" \
	-type f -name '*.go' ! -name '*_test.go' -print0 | xargs -0 grep -n -F '"github.com/anchore/syft/internal/file"'; then
	echo "internal/file import remains in controlled production source" >&2
	exit 63
fi

if find "$SYFT_ROOT/syft/pkg/cataloger/java" \
	-type f -name '*.go' ! -name '*_test.go' -print0 | xargs -0 grep -n -F '"github.com/anchore/syft/syft/format/cyclonedxjson"'; then
	echo "Syft cyclonedxjson import remains in controlled Java production source" >&2
	exit 64
fi

# QUILONS A63: Debian installed-package DB-only reduction
# Syft v1.54.0 NewDBCataloger() is retained unchanged for DPKG/OPKG installed-package inventory.
# NewArchiveCataloger() and parse_deb_archive.go are excluded because the archive-only path pulls
# prohibited dependencies through syft/internal/file -> go-getter and mholt/archives -> sevenzip.
# This patch is intentionally pinned and fails closed on upstream source drift.
DEBIAN_DIR="$SYFT_ROOT/syft/pkg/cataloger/debian"
DEBIAN_CATALOGER="$DEBIAN_DIR/cataloger.go"
DEBIAN_ARCHIVE="$DEBIAN_DIR/parse_deb_archive.go"
DEBIAN_SHARED="$DEBIAN_DIR/quilons_shared_errors.go"

test -f "$DEBIAN_CATALOGER"
test -f "$DEBIAN_ARCHIVE"

python3 - "$DEBIAN_ARCHIVE" "$DEBIAN_SHARED" <<'PY_DEBIAN_SHARED'
from pathlib import Path
import re
import sys

archive = Path(sys.argv[1])
shared = Path(sys.argv[2])
lines = archive.read_text().splitlines()
symbol = "errClippedFileListing"

definition = None
for i, line in enumerate(lines):
    stripped = line.strip()
    if re.match(rf'^(var|const)\s+{symbol}\b', stripped):
        definition = stripped
        break
    if stripped.startswith(symbol):
        j = i - 1
        while j >= 0:
            parent = lines[j].strip()
            if parent in ("var (", "const ("):
                definition = f"{parent.split()[0]} {stripped}"
                break
            if parent == ")" or parent.startswith("func "):
                break
            j -= 1
        if definition:
            break

if not definition or "=" not in definition:
    raise SystemExit("Syft Debian source drift: unsupported errClippedFileListing declaration")

expr = definition.split("=", 1)[1]
imports = [pkg for pkg in ("errors", "fmt") if f"{pkg}." in expr]
if len(imports) > 1:
    raise SystemExit("Syft Debian source drift: shared declaration gained unexpected imports")

output = ["package debian", ""]
if imports:
    output += [f'import "{imports[0]}"', ""]

output += [
    "// QUILONS controlled reduction.",
    "// Exact shared declaration retained from pinned Syft v1.54.0 parse_deb_archive.go.",
    definition,
    "",
]
shared.write_text("\n".join(output))
PY_DEBIAN_SHARED

python3 - "$DEBIAN_CATALOGER" <<'PY_DEBIAN_CATALOGER'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()

db_block = (
'// NewDBCataloger returns a new Deb package cataloger capable of parsing DPKG status DB flat-file stores.\n'
'func NewDBCataloger() pkg.Cataloger {\n'
'\treturn generic.NewCataloger("dpkg-db-cataloger").\n'
'\t\t// note: these globs have been intentionally split up in order to improve search performance,\n'
'\t\t// please do NOT combine into: "**/var/lib/dpkg/{status,status.d/*}"\n'
'\t\tWithParserByGlobs(parseDpkgDB, "**/lib/dpkg/status", "**/lib/dpkg/status.d/*", "**/lib/opkg/info/*.control", "**/lib/opkg/status").\n'
'\t\tWithProcessors(dependency.Processor(dbEntryDependencySpecifier))\n'
'}\n'
)

archive_block = (
'// NewArchiveCataloger returns a new Debian package cataloger object capable of parsing .deb archive files\n'
'func NewArchiveCataloger() pkg.Cataloger {\n'
'\treturn generic.NewCataloger("deb-archive-cataloger").\n'
'\t\tWithParserByGlobs(parseDebArchive, "**/*.deb")\n'
'}\n'
)

if source.count(db_block) != 1:
    raise SystemExit("Syft Debian source drift: exact NewDBCataloger block count != 1")
if source.count(archive_block) != 1:
    raise SystemExit("Syft Debian source drift: exact NewArchiveCataloger block count != 1")

reduced = source.replace("\n" + archive_block, "\n", 1)

if db_block not in reduced:
    raise SystemExit("Syft Debian reduction changed NewDBCataloger")
if archive_block in reduced or "parseDebArchive" in reduced:
    raise SystemExit("Syft Debian archive cataloger reduction incomplete")

path.write_text(reduced)
PY_DEBIAN_CATALOGER

mv "$DEBIAN_ARCHIVE" "$DEBIAN_ARCHIVE.disabled"

grep -F 'func NewDBCataloger() pkg.Cataloger' "$DEBIAN_CATALOGER" >/dev/null
! grep -F 'func NewArchiveCataloger() pkg.Cataloger' "$DEBIAN_CATALOGER"
! grep -F 'parseDebArchive' "$DEBIAN_CATALOGER"
grep -F 'errClippedFileListing' "$DEBIAN_SHARED" >/dev/null

if find "$DEBIAN_DIR" -type f -name '*.go' ! -name '*_test.go' -print0 | \
    xargs -0 grep -n -F '"github.com/anchore/syft/internal/file"'; then
    echo "Syft Debian DB-only production surface still imports syft/internal/file" >&2
    exit 61
fi

if find "$DEBIAN_DIR" -type f -name '*.go' ! -name '*_test.go' -print0 | \
    xargs -0 grep -n -F '"github.com/mholt/archives"'; then
    echo "Syft Debian DB-only production surface still imports mholt/archives" >&2
    exit 62
fi
# QUILONS A68: public controlled-source bridge for Syft internal tempdir context.
# The upstream RPM DB parser requires tmpdir.FromContext(ctx). The bridge is compiled
# inside the pinned Syft module, preserving Go internal-package boundaries.
CATALOGING_DIR="$SYFT_ROOT/syft/cataloging"
test -d "$CATALOGING_DIR"
cat > "$CATALOGING_DIR/quilons_tempdir_context.go" <<'EOF_QUILONS_TEMPDIR'
package cataloging

import (
	"context"

	"github.com/anchore/syft/internal/tmpdir"
)

// WithQuilonsTempDir returns a context carrying Syft's managed TempDir.
// Callers must defer the returned cleanup function.
func WithQuilonsTempDir(ctx context.Context, prefix string) (context.Context, func() error) {
	ctx, td := tmpdir.Root(ctx, prefix)
	return ctx, td.Cleanup
}
EOF_QUILONS_TEMPDIR

grep -F 'func WithQuilonsTempDir(ctx context.Context, prefix string)' "$CATALOGING_DIR/quilons_tempdir_context.go" >/dev/null
grep -F '"github.com/anchore/syft/internal/tmpdir"' "$CATALOGING_DIR/quilons_tempdir_context.go" >/dev/null
