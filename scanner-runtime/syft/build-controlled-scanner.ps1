Clear-Host

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

$ErrorActionPreference = 'Stop'

$Repo = 'C:\Sajith\Quilons AI\quilons-sentrycode'
$GoImage = 'golang@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107'
$ImageTag = 'quilons-controlled-syft:slice2c-a3'
$Work = Join-Path $env:TEMP ('quilons-controlled-syft-a3-' + [guid]::NewGuid().ToString('N'))
$Fixture = Join-Path $Work 'fixture'
$Output = Join-Path $Work 'output'
$ImageContext = Join-Path $Work 'image'

function Fail([string]$Message) {
    Write-Host "FAILED: $Message" -ForegroundColor Red
    throw $Message
}

function Write-Utf8NoBom([string]$Path,[string]$Text) {
    [System.IO.File]::WriteAllText($Path,$Text,(New-Object System.Text.UTF8Encoding($false)))
}

try {
    New-Item -ItemType Directory -Force -Path $Work,$Fixture,$Output,$ImageContext | Out-Null

    Copy-Item -LiteralPath (Join-Path $Repo 'scanner-runtime\syft\cmd\quilons-syft\main.go') -Destination (Join-Path $Work 'main.go')
    Copy-Item -LiteralPath (Join-Path $Repo 'scanner-runtime\syft\Dockerfile.controlled') -Destination (Join-Path $ImageContext 'Dockerfile')
    Copy-Item -LiteralPath (Join-Path $Repo 'scanner-runtime\syft\tools\a12-patch-syft.sh') -Destination (Join-Path $Work 'a12-patch-syft.sh')

    $BuildSh = Join-Path $Work 'build.sh'

    $BuildShLines = @(
        'set -eu',
        'go version',
        'go mod download -json github.com/anchore/syft@v1.54.0 > /work/syft-download.json',
        'MODCACHE="$(go env GOMODCACHE)"',
        'SRC="$MODCACHE/github.com/anchore/syft@v1.54.0"',
        'test -d "$SRC"',
        'cp -a "$SRC" /tmp/syft',
        'chmod -R u+w /tmp/syft',
        'LOCATION=/tmp/syft/syft/file/location.go',
        'test -f "$LOCATION"',
        'IMPORT_COUNT="$(grep -F -c ''"github.com/hashicorp/go-multierror"'' "$LOCATION" || true)"',
        'CALL_COUNT="$(grep -F -c ''errs = multierror.Append(errs, err)'' "$LOCATION" || true)"',
        'test "$IMPORT_COUNT" = "1"',
        'test "$CALL_COUNT" = "1"',
        'awk ''BEGIN{i=0;r=0;p=0} { if ($0 == "\t\"fmt\"") { print "\t\"errors\""; i++ } if ($0 == "\t\"github.com/hashicorp/go-multierror\"") { r++; next } if ($0 ~ /errs = multierror\.Append\(errs, err\)/) { sub(/errs = multierror\.Append\(errs, err\)/, "errs = errors.Join(errs, err)"); p++ } print } END { if (i != 1 || r != 1 || p != 1) exit 42 }'' "$LOCATION" > "$LOCATION.tmp"',
        'mv "$LOCATION.tmp" "$LOCATION"',
        '! grep -F ''github.com/hashicorp/go-multierror'' "$LOCATION"',
        '! grep -F ''multierror.Append'' "$LOCATION"',
        'grep -F ''errors.Join(errs, err)'' "$LOCATION" >/dev/null',
        'grep -F ''"errors"'' "$LOCATION" >/dev/null',
        'sh /work/a12-patch-syft.sh /tmp/syft',
        'mkdir -p /tmp/scanner',
        'cp /work/main.go /tmp/scanner/main.go',
        'cat > /tmp/scanner/go.mod <<''EOF''',
        'module quilons.local/controlled-syft',
        '',
        'go 1.26.0',
        '',
        'require github.com/anchore/syft v1.54.0',
        '',
        'replace github.com/anchore/syft => /tmp/syft',
        'EOF',
        'cd /tmp/scanner',
        'go mod tidy',
        'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /work/quilons-syft .',
        'go version -m /work/quilons-syft > /work/go-version-m.txt',
        'grep -F ''"Version": "v1.54.0"'' /work/syft-download.json >/dev/null'
    )

    Write-Utf8NoBom -Path $BuildSh -Text (($BuildShLines -join "`n") + "`n")

    $BuildOut = Join-Path $Work 'build.stdout.txt'
    $BuildErr = Join-Path $Work 'build.stderr.txt'
    $MountArg = "type=bind,src=$Work,dst=/work"

    $P = Start-Process -FilePath 'docker.exe' `
        -ArgumentList @(
            'run','--rm',
            '--mount',('"' + $MountArg + '"'),
            '-e','GOTOOLCHAIN=local',
            '-e','GOSUMDB=sum.golang.org',
            $GoImage,
            '/bin/sh','/work/build.sh'
        ) `
        -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $BuildOut `
        -RedirectStandardError $BuildErr

    Get-Content -LiteralPath $BuildOut -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
    Get-Content -LiteralPath $BuildErr -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }

    if ($P.ExitCode -ne 0) {
        Fail "Controlled scanner build failed with exit $($P.ExitCode)."
    }

    & node.exe (Join-Path $Repo 'scanner-runtime\syft\tools\verify-policy-modules.mjs') (Join-Path $Work 'go-version-m.txt')
    if ($LASTEXITCODE -ne 0) {
        Fail 'Controlled scanner contains prohibited policy-target modules.'
    }

    Copy-Item -LiteralPath (Join-Path $Work 'quilons-syft') -Destination (Join-Path $ImageContext 'quilons-syft')

    $DockerBuildOut = Join-Path $Work 'docker-image.stdout.txt'
    $DockerBuildErr = Join-Path $Work 'docker-image.stderr.txt'

    $P = Start-Process -FilePath 'docker.exe' `
        -ArgumentList @('build','--pull=false','--network=none','-t',$ImageTag,$ImageContext) `
        -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $DockerBuildOut `
        -RedirectStandardError $DockerBuildErr

    Get-Content -LiteralPath $DockerBuildOut -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
    Get-Content -LiteralPath $DockerBuildErr -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }

    if ($P.ExitCode -ne 0) {
        Fail "Controlled scanner image build failed with exit $($P.ExitCode)."
    }

    $PackageJsonLines = @(
        '{',
        '  "name": "slice2c-vulnerable-fixture",',
        '  "version": "1.0.0",',
        '  "dependencies": { "mkdirp": "0.5.1" }',
        '}'
    )
    [System.IO.File]::WriteAllLines((Join-Path $Fixture 'package.json'),$PackageJsonLines,(New-Object System.Text.UTF8Encoding($false)))

    $PackageLockLines = @(
        '{',
        '  "name": "slice2c-vulnerable-fixture",',
        '  "version": "1.0.0",',
        '  "lockfileVersion": 1,',
        '  "requires": true,',
        '  "dependencies": {',
        '    "mkdirp": {',
        '      "version": "0.5.1",',
        '      "requires": { "minimist": "0.0.8" },',
        '      "dependencies": { "minimist": { "version": "0.0.8" } }',
        '    }',
        '  }',
        '}'
    )
    [System.IO.File]::WriteAllLines((Join-Path $Fixture 'package-lock.json'),$PackageLockLines,(New-Object System.Text.UTF8Encoding($false)))

    $RequirementsLines = @(
        'requests==2.31.0'
    )
    [System.IO.File]::WriteAllLines((Join-Path $Fixture 'requirements.txt'),$RequirementsLines,(New-Object System.Text.UTF8Encoding($false)))

    $CargoLockLines = @(
        '# This file is automatically @generated by Cargo.',
        'version = 3',
        '',
        '[[package]]',
        'name = "serde"',
        'version = "1.0.197"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        'checksum = "9a8e94ea7f378bd32cbbd3711e731bda66d6a63884b03dc64c76ae2ed6c8043d"'
    )
    [System.IO.File]::WriteAllLines((Join-Path $Fixture 'Cargo.lock'),$CargoLockLines,(New-Object System.Text.UTF8Encoding($false)))

    $ConanLines = @(
        '[requires]',
        'zlib/1.2.13'
    )
    [System.IO.File]::WriteAllLines((Join-Path $Fixture 'conanfile.txt'),$ConanLines,(New-Object System.Text.UTF8Encoding($false)))
    $GoModLines = @(
        'module example.com/quilons/a12',
        '',
        'go 1.23',
        '',
        'require github.com/google/uuid v1.6.0'
    )
    [System.IO.File]::WriteAllLines((Join-Path $Fixture 'go.mod'),$GoModLines,(New-Object System.Text.UTF8Encoding($false)))

    $PomLines = @(
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<project xmlns="http://maven.apache.org/POM/4.0.0">',
        '  <modelVersion>4.0.0</modelVersion>',
        '  <groupId>com.quilons.fixture</groupId>',
        '  <artifactId>slice2c-java-fixture</artifactId>',
        '  <version>1.0.0</version>',
        '  <dependencies>',
        '    <dependency>',
        '      <groupId>org.apache.commons</groupId>',
        '      <artifactId>commons-lang3</artifactId>',
        '      <version>3.14.0</version>',
        '    </dependency>',
        '  </dependencies>',
        '</project>'
    )
    [System.IO.File]::WriteAllLines((Join-Path $Fixture 'pom.xml'),$PomLines,(New-Object System.Text.UTF8Encoding($false)))
    $FixtureMount = "type=bind,src=$Fixture,dst=/scan,readonly"
    $OutputMount = "type=bind,src=$Output,dst=/out"
    $RunOut = Join-Path $Work 'run.stdout.txt'
    $RunErr = Join-Path $Work 'run.stderr.txt'

    $P = Start-Process -FilePath 'docker.exe' `
        -ArgumentList @(
            'run','--rm',
            '--network','none',
            '--read-only',
            '--cap-drop','ALL',
            '--security-opt','no-new-privileges:true',
            '--pids-limit','64',
            '--memory','512m',
            '--cpus','1',
            '--mount',('"' + $FixtureMount + '"'),
            '--mount',('"' + $OutputMount + '"'),
            $ImageTag,
            '--input','/scan',
            '--output','/out/sbom.json'
        ) `
        -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $RunOut `
        -RedirectStandardError $RunErr

    Get-Content -LiteralPath $RunOut -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
    Get-Content -LiteralPath $RunErr -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }

    if ($P.ExitCode -ne 0) {
        Fail "Controlled scanner runtime acceptance failed with exit $($P.ExitCode)."
    }

    $SbomPath = Join-Path $Output 'sbom.json'
    if (-not (Test-Path -LiteralPath $SbomPath -PathType Leaf)) {
        Fail 'Controlled scanner did not emit sbom.json.'
    }

    $ValidatePath = Join-Path $Work 'validate.js'
    $ValidateLines = @(
        'const fs=require("fs");',
        'const d=JSON.parse(fs.readFileSync(process.argv[2],"utf8"));',
        'if(d.bomFormat!=="CycloneDX") throw new Error("unexpected bomFormat");',
        'if(d.specVersion!=="1.5") throw new Error("unexpected specVersion");',
        'const n=new Set((d.components||[]).map(c=>c.name));',
        'if(!n.has("mkdirp")) throw new Error("mkdirp missing");',
        'if(!n.has("minimist")) throw new Error("minimist missing");',
        'if(!n.has("requests")) throw new Error("requests missing");',
        'if(!n.has("serde")) throw new Error("serde missing");',
        'if(!n.has("zlib")) throw new Error("zlib missing");',
        'const p=new Set((d.components||[]).map(c=>c.purl).filter(Boolean));',
        'if(!p.has("pkg:golang/github.com/google/uuid@v1.6.0")) throw new Error("Go module fixture missing");',
        'if(!p.has("pkg:maven/org.apache.commons/commons-lang3@3.14.0")) throw new Error("Java Maven fixture missing");',
        'console.log(JSON.stringify({status:"pass",componentCount:(d.components||[]).length}));'
    )
    [System.IO.File]::WriteAllLines($ValidatePath,$ValidateLines,(New-Object System.Text.UTF8Encoding($false)))

    & node.exe $ValidatePath $SbomPath
    if ($LASTEXITCODE -ne 0) {
        Fail 'Controlled scanner CycloneDX acceptance failed.'
    }

    $VersionOut = Join-Path $Work 'version.json'
    $VersionErr = Join-Path $Work 'version.stderr.txt'

    $P = Start-Process -FilePath 'docker.exe' `
        -ArgumentList @('run','--rm','--network','none','--read-only',$ImageTag,'--version') `
        -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $VersionOut `
        -RedirectStandardError $VersionErr

    if ($P.ExitCode -ne 0) {
        Fail 'Controlled scanner version identity failed.'
    }

    $Version = Get-Content -LiteralPath $VersionOut -Raw | ConvertFrom-Json
    if ([string]$Version.upstreamCommit -ne 'cc326e45a6213360266dda4b30cc68095946d676') { Fail 'Upstream commit identity mismatch.' }
    if ([string]$Version.outputFormat -ne 'cyclonedx-json@1.5') { Fail 'Output format identity mismatch.' }
    if ([string]$Version.networkPolicy -ne 'offline') { Fail 'Network policy identity mismatch.' }
    if ([string]$Version.coverage -ne 'javascript-npm,python,rust,c-cpp,go,java,linux-os,alpine-apk,debian-dpkg,redhat-rpm') { Fail 'Coverage identity mismatch.' }

    Write-Host ''
    Write-Host 'CONTROLLED SYFT SCANNER RUNTIME: PASS'
    Write-Host 'Upstream version       : v1.54.0'
    Write-Host 'Upstream commit        : cc326e45a6213360266dda4b30cc68095946d676'
    Write-Host 'Policy-target modules  : 0'
    Write-Host 'Runtime network        : none'
    Write-Host 'Runtime root filesystem: read-only'
    Write-Host 'CycloneDX              : 1.5'
}
finally {
    $RmOut = Join-Path $env:TEMP ('quilons-rm-' + [guid]::NewGuid().ToString('N') + '.out')
    $RmErr = Join-Path $env:TEMP ('quilons-rm-' + [guid]::NewGuid().ToString('N') + '.err')

    if ($env:QUILONS_RETAIN_CONTROLLED_IMAGE -eq '1') {
        Write-Host ("RETAINED CONTROLLED SYFT IMAGE: {0}" -f $ImageTag)
    }
    else {
        try {
            Start-Process -FilePath 'docker.exe' `
                -ArgumentList @('image','rm','-f',$ImageTag) `
                -Wait -PassThru -NoNewWindow `
                -RedirectStandardOutput $RmOut `
                -RedirectStandardError $RmErr | Out-Null
        } catch {
        }
    }

    Remove-Item -LiteralPath $RmOut,$RmErr -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $Work) {
        $LongWork = '\\?\' + $Work
        try {
            Start-Process -FilePath 'cmd.exe' `
                -ArgumentList @('/d','/s','/c',"rd /s /q `"$LongWork`"") `
                -Wait -PassThru -NoNewWindow | Out-Null
        } catch {
        }
    }
}
