# Slice 14 — Java + .NET/C# Ecosystem Support

Implemented first-class Java and .NET/C# coverage across SentryCode's existing enforcement pipeline.

## Java
- Maven `pom.xml` direct dependency discovery with property-resolved versions.
- Gradle direct dependency discovery from Groovy/Kotlin build files.
- Gradle resolved dependency lock discovery from `gradle.lockfile`.
- Maven package URLs and OSV Maven ecosystem synchronization.
- Local Maven cache license enrichment when package POM metadata is available.
- Native Java SAST rules and `.java` language recognition.
- Java monorepo/service classification.

## .NET/C#
- `.csproj` PackageReference discovery.
- `packages.lock.json` direct/transitive NuGet dependency discovery.
- `obj/project.assets.json` resolved dependency discovery.
- NuGet package URLs and OSV NuGet ecosystem synchronization.
- Local NuGet cache `.nuspec` license enrichment when available.
- Native C# SAST rules and `.cs` language recognition.
- .NET monorepo/service classification.

All discovered components flow through the existing dependency allow/deny policy, version policy, registry policy, license policy, local/offline vulnerability database, OSV synchronization, CycloneDX/SPDX SBOM generation, findings/evidence, waivers, release gates, incremental execution, and Compliance publication boundaries.
