# Release and signing checklist

The project currently produces **unsigned development builds**. The GitHub workflow compiles a Windows executable, generates a SHA-256 checksum and uploads it as a CI artifact. A checksum is not a digital signature. No signing credential, vendor account or publication configuration is included.

1. The project is published under the MIT License (see `LICENSE`). Review third-party terms for any new dependency, and never publish live data or keys.
2. Run CI and test a fresh Linux Docker install plus the Windows pairing, startup, tray, repair, pause/resume, revocation and uninstall flows on real devices.
3. Review signing options (e.g. SignPath Foundation for eligible open-source projects, or a commercial trusted signing provider). Acceptance/availability and setup requirements must be confirmed with the provider. Do not claim eligibility or approval until granted.
4. Configure the approved signing workflow with protected environments, trusted build provenance and limited credentials; never place signing keys in the repository or runtime container.
5. Verify Authenticode with Windows tools and test Smart App Control on a clean Windows system. A signature does not guarantee every security policy will accept a binary.
6. Distribute only approved signed artifacts as stable releases, publish checksums and release notes, and replace the container-built unsigned download with a verified signed artifact before public stable distribution. The current Dockerfile cross-builds unsigned binaries by design.
7. Document installation, uninstall, update and rollback. Do not tag a stable release before real platform validation.
