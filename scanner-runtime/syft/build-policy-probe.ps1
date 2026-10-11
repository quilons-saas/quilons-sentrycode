Clear-Host

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

$ErrorActionPreference = 'Stop'

$ExpectedCommit = 'cc326e45a6213360266dda4b30cc68095946d676'
$GoImage = 'golang@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107'
$This = Split-Path -Parent $MyInvocation.MyCommand.Path
$Work = Join-Path $env:TEMP ('quilons-controlled-syft-' + [guid]::NewGuid().ToString('N'))
$Source = Join-Path $Work 'syft'
$Probe = Join-Path $Work 'probe'

try {
    New-Item -ItemType Directory -Force -Path $Work,$Probe | Out-Null

    $CloneOut = Join-Path $Work 'git-clone.stdout.txt'
    $CloneErr = Join-Path $Work 'git-clone.stderr.txt'
    $P = Start-Process -FilePath 'git.exe' -ArgumentList @('clone','--quiet','--filter=blob:none','--no-checkout','https://github.com/anchore/syft.git',$Source) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $CloneOut -RedirectStandardError $CloneErr
    if ($P.ExitCode -ne 0) { throw ('Failed to clone Syft upstream. ' + (Get-Content -LiteralPath $CloneErr -Raw -ErrorAction SilentlyContinue)) }

    $CheckoutOut = Join-Path $Work 'git-checkout.stdout.txt'
    $CheckoutErr = Join-Path $Work 'git-checkout.stderr.txt'
    $P = Start-Process -FilePath 'git.exe' -ArgumentList @('-C',$Source,'checkout','--quiet',$ExpectedCommit) -Wait -PassThru -NoNewWindow -RedirectStandardOutput $CheckoutOut -RedirectStandardError $CheckoutErr
    if ($P.ExitCode -ne 0) { throw ('Failed to checkout exact Syft commit. ' + (Get-Content -LiteralPath $CheckoutErr -Raw -ErrorAction SilentlyContinue)) }

    $Actual = (& git.exe -C $Source rev-parse HEAD).Trim()
    if ($Actual -ne $ExpectedCommit) { throw "Syft commit mismatch: $Actual" }

    & node.exe (Join-Path $This 'tools\patch-syft.mjs') $Source
    if ($LASTEXITCODE -ne 0) { throw 'Controlled Syft patch failed.' }

    $GoModLines = @(
        'module quilons.local/syft-policy-probe',
        '',
        'go 1.26.0',
        '',
        'require github.com/anchore/syft v1.54.0',
        '',
        'replace github.com/anchore/syft => ../syft'
    )
    [System.IO.File]::WriteAllLines((Join-Path $Probe 'go.mod'), $GoModLines, (New-Object System.Text.UTF8Encoding($false)))

    $MainLines = @(
        'package main',
        '',
        'import _ "github.com/anchore/syft/syft/source"',
        '',
        'func main() {}'
    )
    [System.IO.File]::WriteAllLines((Join-Path $Probe 'main.go'), $MainLines, (New-Object System.Text.UTF8Encoding($false)))

    $BuildShell = Join-Path $Work 'build-probe.sh'
    $BuildShellText = @(
        'set -eu',
        'cd /work/probe',
        'go version',
        'go mod tidy',
        'go build -trimpath -o probe .',
        'go version -m probe > go-version-m.txt'
    ) -join "`n"

    [System.IO.File]::WriteAllText(
        $BuildShell,
        ($BuildShellText + "`n"),
        (New-Object System.Text.UTF8Encoding($false))
    )

    $DockerOut = Join-Path $Work 'docker-build.stdout.txt'
    $DockerErr = Join-Path $Work 'docker-build.stderr.txt'
    $MountArg = "type=bind,src=$Work,dst=/work"

    $P = Start-Process -FilePath 'docker.exe' `
        -ArgumentList @(
            'run',
            '--rm',
            '--mount',
            ('"' + $MountArg + '"'),
            '-e',
            'GOTOOLCHAIN=local',
            '-e',
            'GOSUMDB=sum.golang.org',
            $GoImage,
            '/bin/sh',
            '/work/build-probe.sh'
        ) `
        -Wait -PassThru -NoNewWindow `
        -RedirectStandardOutput $DockerOut `
        -RedirectStandardError $DockerErr

    if ($P.ExitCode -ne 0) {
        throw ('Controlled Syft policy probe build failed. ' + (Get-Content -LiteralPath $DockerErr -Raw -ErrorAction SilentlyContinue))
    }
    & node.exe (Join-Path $This 'tools\verify-compiled-modules.mjs') (Join-Path $Probe 'go-version-m.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Controlled Syft policy probe still contains blocked modules.' }

    Write-Host 'CONTROLLED SYFT PATCH FOUNDATION: PASS'
    Write-Host "Upstream commit: $ExpectedCommit"
    Write-Host 'Blocked compiled modules: 0'
}
finally {
    if (Test-Path -LiteralPath $Work) {
        $LongWork = '\\?\' + $Work
        $P = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/d','/s','/c',("rd /s /q `"{0}`"" -f $LongWork)) -Wait -PassThru -NoNewWindow
        if ($P.ExitCode -ne 0 -and (Test-Path -LiteralPath $Work)) { Write-Warning "Temporary work directory remains: $Work" }
    }
}
