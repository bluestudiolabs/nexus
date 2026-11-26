# Security policy (developer preview)

This is a pre-release, single-owner, local-network dashboard; not a hardened internet-facing appliance. No public exposure is supported. Report vulnerabilities privately through GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not include tokens, logs with identifying information, private keys or database exports in public issues.

- TLS hostname/IP verification, hashed enrollment tokens, one-time pairing codes, rate-limited authentication, secure cookies, strict origin/Host checks, optional TOTP and recovery codes.
- The web process runs with a non-root UID, read-only root filesystem, dropped capabilities, and no host Docker socket. Only the data mount is writable. The optional collector is a separate user process with the user's existing OS permissions.
- Keep `.nexus/`, backups, certificates, tokens and actual logs out of version control. No device identifiers are shipped. Synthetic tests use documentation networks and example names.
- Privacy filters currently apply on the server after data arrives. They do not guarantee that the client stops collecting or transmitting the excluded fields.
- User-defined external endpoints should be trusted; weather and external status calls are opt-in. Do not treat discovery/MAC addresses as authentication. Container isolation is not a VM boundary.
- No privileged web uninstall, arbitrary remote command execution or plugin execution. Local lifecycle management requires the trusted installation owner.
- Smart App Control and code signing are distinct from server TLS. Do not disable security protections to execute unsigned development builds.
- Before release: run real Docker and Windows lifecycle tests; test LAN/firewall isolation, certificate rotation, backups/restore, dependency review, signing and incident reporting.
