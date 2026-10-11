Clear-Host

if ($args.Count -lt 1) {
    throw "usage: build-scanner-attribution.ps1 <OutputRoot> [-AllowNetworkForLicenseSources] [SyftImage] [GrypeImage] [RunnerImageRef]"
}

$OutputRoot = [string]$args[0]
$AllowNetworkForLicenseSources = $false
$SyftImage = "quilons-controlled-syft:slice2c-a3"
$GrypeImage = "quilons-controlled-grype:slice2c-a15"
$RunnerImageRef = ""

$Positionals = New-Object System.Collections.Generic.List[string]
for ($i = 1; $i -lt $args.Count; $i++) {
    $Value = [string]$args[$i]
    if ($Value -eq "-AllowNetworkForLicenseSources") {
        $AllowNetworkForLicenseSources = $true
    } else {
        $Positionals.Add($Value)
    }
}

if ($Positionals.Count -gt 0) { $SyftImage = $Positionals[0] }
if ($Positionals.Count -gt 1) { $GrypeImage = $Positionals[1] }
if ($Positionals.Count -gt 2) { $RunnerImageRef = $Positionals[2] }
if ($Positionals.Count -gt 3) { throw "Too many positional arguments." }
$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$GoImage = "golang@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107"
$BlockedModules = @(
    "github.com/anchore/go-version",
    "github.com/hashicorp/aws-sdk-go-base/v2",
    "github.com/hashicorp/errwrap",
    "github.com/hashicorp/go-cleanhttp",
    "github.com/hashicorp/go-getter",
    "github.com/hashicorp/go-multierror",
    "github.com/hashicorp/go-version",
    "github.com/hashicorp/golang-lru/v2",
    "github.com/hashicorp/hcl/v2"
)

# QUILONS_A9_LICENSE_HARDENING
function Get-QuilonsA9LicenseIdsFromText([string]$Text) {
    $Ids = New-Object System.Collections.Generic.List[string]

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }

    if ($Text -match '(?is)Apache License.{0,400}Version 2\.0') {
        [void]$Ids.Add('Apache-2.0')
    }

    if (
        $Text -match '(?is)\bMIT License\b' -or
        (
            $Text -match '(?is)Permission is hereby granted,\s*free of charge,\s*to any person obtaining a copy' -and
            $Text -match '(?is)THE SOFTWARE IS PROVIDED ["'']AS IS["'']'
        )
    ) {
        [void]$Ids.Add('MIT')
    }

    if (
        $Text -match '(?is)Redistribution and use in source and binary forms,\s*with or without modification,\s*are permitted' -and
        $Text -match '(?is)Neither the name|Neither the names'
    ) {
        [void]$Ids.Add('BSD-3-Clause')
    }

    if (
        $Text -match '(?is)Redistribution and use in source and binary forms,\s*with or without modification,\s*are permitted' -and
        $Text -match '(?is)THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ["'']AS IS["'']' -and
        -not ($Text -match '(?is)Neither the name|Neither the names')
    ) {
        [void]$Ids.Add('BSD-2-Clause')
    }

    if (
        $Text -match '(?is)Permission to use,\s*copy,\s*modify,\s*and/or distribute this software for any purpose' -and
        $Text -match '(?is)THE SOFTWARE IS PROVIDED ["'']AS IS["'']'
    ) {
        [void]$Ids.Add('ISC')
    }

    if (
        $Text -match '(?is)Creative Commons CC0 1\.0 Universal' -or
        $Text -match '(?is)CC0 1\.0 Universal' -or
        (
            $Text -match '(?is)public domain' -and
            $Text -match '(?is)waive|dedicat|relinquish'
        )
    ) {
        [void]$Ids.Add('CC0-1.0')
    }

    if (
        $Text -match '(?is)SQLite Is Public Domain' -or
        $Text -match '(?is)The author disclaims copyright to this source code'
    ) {
        [void]$Ids.Add('Public-Domain')
    }

    if ($Text -match '(?is)Mozilla Public License.{0,200}2\.0') {
        [void]$Ids.Add('MPL-2.0')
    }

    if ($Text -match '(?is)GNU AFFERO GENERAL PUBLIC LICENSE') {
        [void]$Ids.Add('AGPL')
    }
    elseif ($Text -match '(?is)GNU LESSER GENERAL PUBLIC LICENSE') {
        [void]$Ids.Add('LGPL')
    }
    elseif ($Text -match '(?is)GNU GENERAL PUBLIC LICENSE') {
        [void]$Ids.Add('GPL')
    }

    return @($Ids | Sort-Object -Unique)
}

function Test-QuilonsA9NonCodeLicenseFile([string]$FileName) {
    return $FileName -match '(?i)^LICENSE[._-]?docs?$'
}
function Fail([string]$Message) { throw $Message }
# QUILONS_A19_UTF8_NO_BOM
function WriteJsonUtf8NoBom([string]$Path,[object]$Value,[int]$Depth=12) {
    $Json = $Value | ConvertTo-Json -Depth $Depth
    [System.IO.File]::WriteAllText(
        $Path,
        $Json,
        (New-Object System.Text.UTF8Encoding($false))
    )
}
function Sha256([string]$Path) { return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() }
function SafeName([string]$Value) { return ($Value -replace '[^A-Za-z0-9._-]', '_') }
function ClassifyLicense([string]$Text) {
    $Lower = $Text.ToLowerInvariant()
    if ($Lower -match "mozilla public license" -or $Lower -match "mpl 2\.0") { return @{ id = "MPL-2.0"; status = "prohibited" } }
    if ($Lower -match "gnu affero general public license") { return @{ id = "AGPL"; status = "prohibited" } }
    if ($Lower -match "gnu lesser general public license") { return @{ id = "LGPL"; status = "prohibited" } }
    if ($Lower -match "gnu general public license") { return @{ id = "GPL"; status = "prohibited" } }
    if ($Lower -match "apache license" -and $Lower -match "version 2\.0") { return @{ id = "Apache-2.0"; status = "permitted" } }
    if ($Lower -match "permission is hereby granted, free of charge") { return @{ id = "MIT"; status = "permitted" } }
    if ($Lower -match "redistribution and use in source and binary forms" -and $Lower -match "neither the name") { return @{ id = "BSD-3-Clause"; status = "permitted" } }
    if ($Lower -match "redistribution and use in source and binary forms") { return @{ id = "BSD-2-Clause"; status = "permitted" } }
    if ($Lower -match "permission to use, copy, modify, and/or distribute this software") { return @{ id = "ISC"; status = "permitted" } }
    return @{ id = "UNKNOWN"; status = "unresolved" }
}
function DockerInspect([string]$Image) {
    $Raw = & docker.exe image inspect $Image 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "Docker image inspect failed for $Image`n$($Raw | Out-String)" }
    return (($Raw | Out-String) | ConvertFrom-Json)[0]
}
function ExtractBinary([string]$Image,[string]$Destination,[string]$FallbackPath) {
    $Inspect = DockerInspect $Image
    $Entrypoint = @($Inspect.Config.Entrypoint)
    $Candidate = if ($Entrypoint.Count -gt 0 -and [string]$Entrypoint[0]) { [string]$Entrypoint[0] } else { $FallbackPath }
    $Container = (& docker.exe create $Image 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $Container) { Fail "docker create failed for $Image" }
    try {
        & docker.exe cp "${Container}:$Candidate" $Destination | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Destination -PathType Leaf)) { Fail "Failed to extract scanner binary $Candidate from $Image" }
    } finally { & docker.exe rm -f $Container | Out-Null }
    return $Candidate
}
function GetGoModules([string]$BinaryPath,[string]$Name) {
    $Dir = Split-Path -Parent $BinaryPath
    $File = Split-Path -Leaf $BinaryPath
    $Mount = "type=bind,src=$Dir,dst=/work,readonly"
    $Raw = & docker.exe run --rm --network none --mount $Mount $GoImage go version -m "/work/$File" 2>&1
    if ($LASTEXITCODE -ne 0) { Fail "go version -m failed for $Name`n$($Raw | Out-String)" }
    $Modules = New-Object System.Collections.Generic.List[object]
    foreach ($LineObject in @($Raw)) {
        $Line = [string]$LineObject
        if ($Line -match '^\s*dep\s+(\S+)\s+(\S+)(?:\s+(\S+))?') {
            $Modules.Add([pscustomobject]@{ path=$Matches[1]; version=$Matches[2]; sum=if($Matches.Count -gt 3){$Matches[3]}else{""} })
        }
    }
    $Modules
}
# QUILONS_A16_LICENSE_SCOPE
function AcquireModuleLicenses([object[]]$Modules,[string]$Scanner,[string]$Root) {
    $Results = New-Object System.Collections.Generic.List[object]
    $Index = 0
    foreach ($Module in $Modules) {
        $Index++
        $ModulePath = [string]$Module.path
        $Version = [string]$Module.version
        if ($ModulePath.StartsWith("quilons.")) { continue }
        # QUILONS_A13_ATTRIBUTION_PROGRESS
        $A13Started = Get-Date
        Write-Host ("[{0}] {1} {2}@{3} - attribution start" -f $Index,$Scanner,$ModulePath,$Version)
        $Blocked = $BlockedModules -contains $ModulePath
        $TargetRel = Join-Path $Scanner ("{0:D4}_{1}" -f $Index,(SafeName $ModulePath))
        $Target = Join-Path $Root $TargetRel
        New-Item -ItemType Directory -Force -Path $Target | Out-Null
        $DownloadError = $null
        if ($AllowNetworkForLicenseSources) {
            $Mount = "type=bind,src=$Target,dst=/out"
            $Spec = "$ModulePath@$Version"
            $AcquireScript = Join-Path $Root "_acquire-module-license.sh"
            if (-not (Test-Path -LiteralPath $AcquireScript -PathType Leaf)) {
                $HelperBytes = [Convert]::FromBase64String("IyEvYmluL3NoCnNldCAtZXUKCnNwZWM9IiQxIgpqc29uX2ZpbGU9Ii90bXAvcXVpbG9ucy1nby1tb2R1bGUuanNvbiIKCmdvIG1vZCBkb3dubG9hZCAtanNvbiAiJHNwZWMiID4gIiRqc29uX2ZpbGUiCgpkaXI9IiQoc2VkIC1uICdzL15bWzpzcGFjZTpdXSoiRGlyIjpbWzpzcGFjZTpdXSoiXCguKlwpIixbWzpzcGFjZTpdXSokL1wxL3AnICIkanNvbl9maWxlIikiCmlmIFsgLXogIiRkaXIiIF0gfHwgWyAhIC1kICIkZGlyIiBdOyB0aGVuCiAgZWNobyAibW9kdWxlIHNvdXJjZSBEaXIgbWlzc2luZyBmb3IgJHNwZWMiID4mMgogIGNhdCAiJGpzb25fZmlsZSIgPiYyCiAgZXhpdCAzMQpmaQoKY29weV9maWxlKCkgewogIGZpbGU9IiQxIgogIHJlbD0iJHtmaWxlIyIkZGlyIi99IgogIHNhZmU9IiQocHJpbnRmICclcycgIiRyZWwiIHwgdHIgJy9cXCcgJ19fJykiCiAgY3AgIiRmaWxlIiAiL291dC8kc2FmZSIKfQoKIyAxKSBBdXRob3JpdGF0aXZlIG1vZHVsZS1yb290IGF0dHJpYnV0aW9uIGZpbGVzIG9ubHkuCmZvciBmaWxlIGluIFwKICAiJGRpciIvTElDRU5TRSAiJGRpciIvTElDRU5TRS4qICIkZGlyIi9MSUNFTlNFLSogXAogICIkZGlyIi9MSUNFTkNFICIkZGlyIi9MSUNFTkNFLiogIiRkaXIiL0xJQ0VOQ0UtKiBcCiAgIiRkaXIiL0NPUFlJTkcgIiRkaXIiL0NPUFlJTkcuKiAiJGRpciIvQ09QWUlORy0qIFwKICAiJGRpciIvTk9USUNFICIkZGlyIi9OT1RJQ0UuKiAiJGRpciIvTk9USUNFLSogXAogICIkZGlyIi9DT1BZUklHSFQgIiRkaXIiL0NPUFlSSUdIVC4qICIkZGlyIi9DT1BZUklHSFQtKgpkbwogIFsgLWYgIiRmaWxlIiBdICYmIGNvcHlfZmlsZSAiJGZpbGUiCmRvbmUKCiMgMikgTmFycm93IGZhbGxiYWNrOiBpZiByb290IGhhcyBub3RoaW5nLCBpbnNwZWN0IG9ubHkgZGlyZWN0IGNoaWxkIGRpcnMgZm9yIGEKIyAgICBjb252ZW50aW9uYWwgcHJpbWFyeSBMSUNFTlNFL0xJQ0VOQ0UvQ09QWUlORyBmaWxlLiBEbyBOT1QgcmVjdXJzZSBmdXJ0aGVyCiMgICAgYW5kIGRvIE5PVCBjb2xsZWN0IE5PVElDRS9DT1BZUklHSFQgZnJvbSBuZXN0ZWQgdmVuZG9yZWQvZXhhbXBsZSB0cmVlcy4KY291bnQ9IiQoZmluZCAvb3V0IC1tYXhkZXB0aCAxIC10eXBlIGYgfCB3YyAtbCB8IHRyIC1kICcgJykiCmlmIFsgIiRjb3VudCIgLWVxIDAgXTsgdGhlbgogIGZpbmQgIiRkaXIiIC1taW5kZXB0aCAyIC1tYXhkZXB0aCAyIC10eXBlIGYgXCggXAogICAgLWluYW1lICdMSUNFTlNFJyAtbyAtaW5hbWUgJ0xJQ0VOU0UudHh0JyAtbyAtaW5hbWUgJ0xJQ0VOU0UubWQnIC1vIFwKICAgIC1pbmFtZSAnTElDRU5DRScgLW8gLWluYW1lICdMSUNFTkNFLnR4dCcgLW8gLWluYW1lICdMSUNFTkNFLm1kJyAtbyBcCiAgICAtaW5hbWUgJ0NPUFlJTkcnIC1vIC1pbmFtZSAnQ09QWUlORy50eHQnIFwKICBcKSAtcHJpbnQgfCBzb3J0IHwgd2hpbGUgSUZTPSByZWFkIC1yIGZpbGUKICBkbwogICAgY29weV9maWxlICIkZmlsZSIKICBkb25lCmZpCgpjb3VudD0iJChmaW5kIC9vdXQgLW1heGRlcHRoIDEgLXR5cGUgZiB8IHdjIC1sIHwgdHIgLWQgJyAnKSIKaWYgWyAiJGNvdW50IiAtZXEgMCBdOyB0aGVuCiAgZWNobyAibm8gbW9kdWxlIGF0dHJpYnV0aW9uIGZpbGVzIGZvdW5kIGZvciAkc3BlYyIgPiYyCiAgZXhpdCAzMgpmaQo=")
                [System.IO.File]::WriteAllBytes($AcquireScript,$HelperBytes)
            }
            $ToolMount = "type=bind,src=$AcquireScript,dst=/tool/acquire-module-license.sh,readonly"
            $NetworkArgs = @("run","--rm","--mount",$Mount,"--mount",$ToolMount,$GoImage,"sh","/tool/acquire-module-license.sh",$Spec)
            $OldNativePreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = "Continue"
                $Out = & docker.exe @NetworkArgs 2>&1
                $DockerExit = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $OldNativePreference
            }
            $A13Elapsed = [Math]::Round(((Get-Date) - $A13Started).TotalSeconds,1)
            if ($DockerExit -eq 0) {
                Write-Host ("[{0}] {1} {2}@{3} - source acquisition OK ({4}s)" -f $Index,$Scanner,$ModulePath,$Version,$A13Elapsed)
            }
            else {
                Write-Host ("[{0}] {1} {2}@{3} - source acquisition FAILED ({4}s)" -f $Index,$Scanner,$ModulePath,$Version,$A13Elapsed)
            }
            if ($DockerExit -ne 0) { $DownloadError = ($Out | Out-String).Trim() }
        } else { $DownloadError = "license source acquisition disabled; rerun with -AllowNetworkForLicenseSources" }
        $Files = if (Test-Path -LiteralPath $Target -PathType Container) { @(Get-ChildItem -LiteralPath $Target -File | Sort-Object Name) } else { @() }
        $LicenseIds = New-Object System.Collections.Generic.HashSet[string]
        $Statuses = New-Object System.Collections.Generic.HashSet[string]
        $Copyrights = New-Object System.Collections.Generic.HashSet[string]
        $FileRecords = New-Object System.Collections.Generic.List[object]
        foreach ($File in $Files) {
            $Text = Get-Content -LiteralPath $File.FullName -Raw -ErrorAction SilentlyContinue
            if ($null -eq $Text) { $Text = "" }
            $IsNotice = $File.Name -match '^(NOTICE|COPYRIGHT)'
            if (-not $IsNotice) {
                $Class = ClassifyLicense $Text
                [void]$LicenseIds.Add([string]$Class.id)
                [void]$Statuses.Add([string]$Class.status)
            }
            foreach ($Line in ($Text -split "`r?`n")) { if ($Line -match '(?i)copyright') { [void]$Copyrights.Add($Line.Trim()) } }
            $FileRecords.Add([pscustomobject]@{ path=("LICENSES/" + (($TargetRel -replace '\\','/') + "/" + $File.Name)); absolutePath=$File.FullName; sha256=Sha256 $File.FullName; notice=[bool]$IsNotice })
        }

    # QUILONS_A9_LICENSE_HARDENING: augment classification from exact collected texts only.
    foreach ($A9FileRecord in $FileRecords) {
        $A9Path = $null

        foreach ($A9Property in @('path','filePath','absolutePath','sourcePath','outputPath')) {
            if ($null -ne $A9FileRecord.PSObject.Properties[$A9Property]) {
                $A9Candidate = [string]$A9FileRecord.$A9Property
                if (-not [string]::IsNullOrWhiteSpace($A9Candidate)) {
                    $A9Path = $A9Candidate
                    break
                }
            }
        }

        if (
            -not [string]::IsNullOrWhiteSpace($A9Path) -and
            (Test-Path -LiteralPath $A9Path -PathType Leaf)
        ) {
            $A9FileName = [System.IO.Path]::GetFileName($A9Path)

            if (-not (Test-QuilonsA9NonCodeLicenseFile $A9FileName)) {
                $A9Text = [System.IO.File]::ReadAllText($A9Path)

                $A9ResolvedIds = @(Get-QuilonsA9LicenseIdsFromText $A9Text)

                if ($A9ResolvedIds.Count -gt 0) {
                    foreach ($A9Id in $A9ResolvedIds) {
                        if (-not $LicenseIds.Contains($A9Id)) {
                            [void]$LicenseIds.Add($A9Id)
                        }
                    }

                    # UNKNOWN came from the older classifier for the same exact collected text.
                    # Remove it only when this exact text has now resolved to one or more known IDs.
                    if ($LicenseIds.Contains("UNKNOWN")) {
                        [void]$LicenseIds.Remove("UNKNOWN")
                    }
                }
            }
        }
    }
        # QUILONS_A12_STATUS_RECOMPUTE
        # Recompute final status only after exact-text augmentation.
        $HasProhibitedId =
            $LicenseIds.Contains("MPL-2.0") -or
            $LicenseIds.Contains("GPL") -or
            $LicenseIds.Contains("LGPL") -or
            $LicenseIds.Contains("AGPL")

        $HasUnknownId = $LicenseIds.Contains("UNKNOWN")

        $Status = if ($Blocked) {
            "prohibited"
        }
        elseif ($HasProhibitedId -or $Statuses.Contains("prohibited")) {
            "prohibited"
        }
        elseif ($HasUnknownId -or $LicenseIds.Count -eq 0) {
            "unresolved"
        }
        else {
            "permitted"
        }
        $LicenseIdArray = @()
        foreach ($LicenseId in $LicenseIds) {
            $LicenseIdArray += [string]$LicenseId
        }
        $LicenseIdArray = @($LicenseIdArray | Sort-Object)

        $LicenseFileArray = @()
        foreach ($FileRecord in $FileRecords) {
            $LicenseFileArray += $FileRecord
        }

        $CopyrightArray = @()
        foreach ($CopyrightValue in $Copyrights) {
            $CopyrightArray += [string]$CopyrightValue
        }
        $CopyrightArray = @($CopyrightArray | Sort-Object)

        $A13TotalElapsed = [Math]::Round(((Get-Date) - $A13Started).TotalSeconds,1)
        Write-Host ("[{0}] {1} {2}@{3} - {4} licenses=[{5}] ({6}s total)" -f $Index,$Scanner,$ModulePath,$Version,$Status,([string]::Join(",",@($LicenseIdArray))),$A13TotalElapsed)
        $Results.Add([pscustomobject]@{ scanner=$Scanner; name=$ModulePath; version=$Version; goSum=[string]$Module.sum; status=$Status; licenseIds=$LicenseIdArray; licenseFiles=$LicenseFileArray; copyright=$CopyrightArray; acquisitionError=$DownloadError })
    }
    $Results
}

$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
if (Test-Path -LiteralPath $OutputRoot) { Remove-Item -LiteralPath $OutputRoot -Recurse -Force }
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$ImagesDir = Join-Path $OutputRoot "images"
$BinsDir = Join-Path $OutputRoot "binaries"
$LicensesDir = Join-Path $OutputRoot "LICENSES"
$EvidenceDir = Join-Path $OutputRoot "evidence"
New-Item -ItemType Directory -Force -Path $ImagesDir,$BinsDir,$LicensesDir,$EvidenceDir | Out-Null

$Scanners = @(
    @{ id="syft"; image=$SyftImage; fallback="/quilons-syft"; metadata=(Join-Path $Repo "scanner-runtime\syft\controlled-source.json") },
    @{ id="grype"; image=$GrypeImage; fallback="/quilons-grype"; metadata=(Join-Path $Repo "scanner-runtime\grype\controlled-source.json") }
)
$Provenance = New-Object System.Collections.Generic.List[object]
$AllComponents = New-Object System.Collections.Generic.List[object]
$AllModulesForSbom = New-Object System.Collections.Generic.List[object]

foreach ($Scanner in $Scanners) {
    $Id = [string]$Scanner.id; $Image = [string]$Scanner.image; $Inspect = DockerInspect $Image
    $Archive = Join-Path $ImagesDir "$Id.tar"
    # QUILONS_A15_SCANNER_STAGE_PROGRESS
    $A15ScannerStarted = Get-Date
    Write-Host ("=== {0}: image save START [{1}] ===" -f $Id,$Image)
    & docker.exe image save -o $Archive $Image
    $A15ImageSaveElapsed = [Math]::Round(((Get-Date) - $A15ScannerStarted).TotalSeconds,1)
    Write-Host ("=== {0}: image save END ({1}s) ===" -f $Id,$A15ImageSaveElapsed)
    if ($LASTEXITCODE -ne 0) { Fail "docker image save failed for $Image" }
    $Binary = Join-Path $BinsDir $Id
    $Entrypoint = ExtractBinary $Image $Binary ([string]$Scanner.fallback)
    Write-Host ("=== {0}: binary ready [{1}] ===" -f $Id,$Binary)
    Write-Host ("=== {0}: go version -m START ===" -f $Id)
    $A15ModuleStarted = Get-Date
    $Modules = @(GetGoModules $Binary $Id)
    $A15ModuleElapsed = [Math]::Round(((Get-Date) - $A15ModuleStarted).TotalSeconds,1)
    Write-Host ("=== {0}: go version -m END modules={1} ({2}s) ===" -f $Id,$Modules.Count,$A15ModuleElapsed)
    if ($Id -eq "grype" -and -not ($Modules | Where-Object { $_.path -eq "github.com/masahiro331/go-mvn-version" })) {
        $Modules += [pscustomobject]@{ path="github.com/masahiro331/go-mvn-version"; version="v0.0.0-20250131095131-f4974fa13b8a"; sum="vendored-source-derived" }
    }
    foreach ($Module in $Modules) { $AllModulesForSbom.Add([pscustomobject]@{ scanner=$Id; path=[string]$Module.path; version=[string]$Module.version; sum=[string]$Module.sum }) }
    Write-Host ("=== {0}: module attribution START modules={1} ===" -f $Id,$Modules.Count)
    $A15AttributionStarted = Get-Date
    foreach ($Component in @(AcquireModuleLicenses $Modules $Id $LicensesDir)) { $AllComponents.Add($Component) }
    $A15AttributionElapsed = [Math]::Round(((Get-Date) - $A15AttributionStarted).TotalSeconds,1)
    Write-Host ("=== {0}: module attribution END ({1}s) ===" -f $Id,$A15AttributionElapsed)
    $MetadataSha = $null
    if (Test-Path -LiteralPath ([string]$Scanner.metadata) -PathType Leaf) { $MetadataSha = Sha256 ([string]$Scanner.metadata); Copy-Item -LiteralPath ([string]$Scanner.metadata) -Destination (Join-Path $EvidenceDir "$Id-controlled-source.json") }
    $Provenance.Add([pscustomobject]@{ scanner=$Id; requestedImageRef=$Image; imageId=[string]$Inspect.Id; repoDigests=@($Inspect.RepoDigests); entrypoint=$Entrypoint; archivePath="images/$Id.tar"; archiveSha256=Sha256 $Archive; binaryPath="binaries/$Id"; binarySha256=Sha256 $Binary; controlledSourceSha256=$MetadataSha; compiledModuleCount=@($Modules).Count })
}

$Dockerfile = Join-Path $Repo "Dockerfile"

# QUILONS_A18_RUNNER_PROVENANCE_PS51
$RunnerDockerfileSha = $null
$RunnerFromLines = @()
$RunnerDockerCliLines = @()
$RunnerExactImage = $null

if (Test-Path -LiteralPath $Dockerfile -PathType Leaf) {
    $RunnerDockerfileSha = Sha256 $Dockerfile
    foreach ($DockerfileLineObject in @(Get-Content -LiteralPath $Dockerfile)) {
        $DockerfileLineText = [string]$DockerfileLineObject
        if ($DockerfileLineText -match '^\s*FROM\s+') {
            $RunnerFromLines += $DockerfileLineText
        }
        if ($DockerfileLineText -match '(?i)docker|git') {
            $RunnerDockerCliLines += $DockerfileLineText
        }
    }
}

if ($RunnerImageRef.Trim()) {
    $RunnerInspect = DockerInspect $RunnerImageRef
    $RunnerRepoDigests = @()
    foreach ($RunnerRepoDigest in @($RunnerInspect.RepoDigests)) {
        $RunnerRepoDigests += [string]$RunnerRepoDigest
    }

    $RunnerExactImage = [pscustomobject]@{
        requestedRef = [string]$RunnerImageRef
        imageId = [string]$RunnerInspect.Id
        repoDigests = $RunnerRepoDigests
    }
}

$RunnerProvenance = [pscustomobject]@{
    dockerfilePath = "Dockerfile"
    dockerfileSha256 = $RunnerDockerfileSha
    fromLines = $RunnerFromLines
    dockerCliLines = $RunnerDockerCliLines
    exactRunnerImage = $RunnerExactImage
}
$ModificationFiles = @(
    "scanner-runtime\syft\controlled-source.json","scanner-runtime\syft\controlled-patch-manifest.json","scanner-runtime\syft\build-controlled-scanner.ps1","scanner-runtime\syft\cmd\quilons-syft\main.go","scanner-runtime\syft\tools\a12-patch-syft.sh","scanner-runtime\syft\tools\patch-syft.mjs",
    "scanner-runtime\grype\controlled-source.json","scanner-runtime\grype\build-controlled-grype.ps1","scanner-runtime\grype\cmd\quilons-grype\main.go","scanner-runtime\grype\tools\patch-grype.mjs"
)
$Modifications=@(); foreach($Rel in $ModificationFiles){$Path=Join-Path $Repo $Rel;if(Test-Path -LiteralPath $Path -PathType Leaf){$Modifications += [pscustomobject]@{path=($Rel-replace '\\','/');sha256=Sha256 $Path}}}

$ThirdPartyComponentsArray = @()
foreach ($ThirdPartyComponent in $AllComponents) {
    $ThirdPartyComponentsArray += $ThirdPartyComponent
}

$BlockedModulesArray = @()
foreach ($BlockedModule in $BlockedModules) {
    $BlockedModulesArray += [string]$BlockedModule
}
$BlockedModulesArray = @($BlockedModulesArray | Sort-Object)
$ThirdParty=[ordered]@{schemaVersion=1;generatedAt=(Get-Date).ToUniversalTime().ToString("o");policy=[ordered]@{permissiveOnly=$true;mpl2Prohibited=$true;blockedModules=$BlockedModulesArray;unknownBlocksRelease=$true};components=$ThirdPartyComponentsArray}
WriteJsonUtf8NoBom (Join-Path $OutputRoot "THIRD_PARTY_COMPONENTS.json") $ThirdParty 12

$Notices=New-Object System.Collections.Generic.List[string]
$Notices.Add("QUILONS SentryCode controlled scanner third-party notices")
$Notices.Add("Generated from exact compiled scanner module identities and exact acquired license/notice texts.")
$Notices.Add("The Grype vulnerability database is operator-provisioned and is NOT included in this distribution.")
$Notices.Add("")
foreach($C in @($AllComponents|Sort-Object scanner,name,version)){$Notices.Add("--------------------------------------------------------------------------------");$Notices.Add("$($C.name) $($C.version)");$Notices.Add("Scanner: $($C.scanner)");$Notices.Add("Status: $($C.status)");$Notices.Add("License: $([string]::Join(', ', @($C.licenseIds)))");foreach($Copy in @($C.copyright)){$Notices.Add($Copy)};foreach($LF in @($C.licenseFiles)){$Notices.Add("License/notice file: $($LF.path) sha256:$($LF.sha256)")};$Notices.Add("")}
[System.IO.File]::WriteAllLines((Join-Path $OutputRoot "THIRD_PARTY_NOTICES.txt"),$Notices,(New-Object System.Text.UTF8Encoding($false)))
WriteJsonUtf8NoBom (Join-Path $OutputRoot "SCANNER_PROVENANCE.json") $Provenance 10
WriteJsonUtf8NoBom (Join-Path $OutputRoot "RUNNER_PROVENANCE.json") $RunnerProvenance 10
WriteJsonUtf8NoBom (Join-Path $OutputRoot "MODIFICATIONS.json") $Modifications 10

$BinarySbomComponents=@();foreach($M in @($AllModulesForSbom|Sort-Object scanner,path,version -Unique)){$BinarySbomComponents += [ordered]@{type="library";name=$M.path;version=$M.version;properties=@(@{name="quilons:scanner";value=$M.scanner},@{name="quilons:go-sum";value=$M.sum})}}
[ordered]@{bomFormat="CycloneDX";specVersion="1.5";version=1;metadata=@{component=@{type="application";name="QUILONS controlled scanner binaries"}};components=$BinarySbomComponents}|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $OutputRoot "SCANNER_BINARY_SBOM.cdx.json") -Encoding UTF8
$ImageSbomComponents=@();foreach($P in $Provenance){$ImageSbomComponents += [ordered]@{type="container";name="quilons-controlled-$($P.scanner)";version=[string]$P.imageId;hashes=@(@{alg="SHA-256";content=$P.archiveSha256});properties=@(@{name="quilons:image-ref";value=$P.requestedImageRef},@{name="quilons:image-id";value=$P.imageId})}}
[ordered]@{bomFormat="CycloneDX";specVersion="1.5";version=1;metadata=@{component=@{type="application";name="QUILONS controlled scanner images"}};components=$ImageSbomComponents}|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $OutputRoot "SCANNER_IMAGE_SBOM.cdx.json") -Encoding UTF8
[ordered]@{bomFormat="CycloneDX";specVersion="1.5";version=1;metadata=@{component=@{type="application";name="QUILONS SentryCode scanner pack"};properties=@(@{name="quilons:grype-db-distribution";value="excluded-operator-provisioned"})};components=@($ImageSbomComponents+$BinarySbomComponents)}|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $OutputRoot "DISTRIBUTION_SBOM.cdx.json") -Encoding UTF8

& node.exe (Join-Path $PSScriptRoot "verify-scanner-attribution.mjs") $OutputRoot
if($LASTEXITCODE -ne 0){Fail "Scanner attribution release gate failed."}
Write-Host "PASS - exact scanner attribution package generated and verified."
Write-Host "Output: $OutputRoot"
Write-Host "Grype DB distribution: EXCLUDED"
