# Changelog

## 3.0 clean developer preview

- Removed installation-specific seed devices, endpoints, paths, clocks, LAN and disk assumptions.
- Added independent setup with private runtime, generated TLS and owner authentication, generic Compose project and lifecycle utility.
- Preserved dashboard, widgets, themes, multi-device monitoring, history, rules, privacy filtering and TOTP.
- Integrated native Windows agent source and automated unsigned build; removed script-based Windows installer distribution.
- Added clean-start regression tests and CI. Disabled the privileged browser uninstall bridge in this edition. Public signing and real deployment validation remain outstanding.
- Published under the MIT License; security reports go through GitHub private vulnerability reporting.
