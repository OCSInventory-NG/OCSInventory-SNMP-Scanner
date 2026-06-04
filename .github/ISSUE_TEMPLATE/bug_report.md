---
name: Bug report
about: Report a bug to help us improve the OCS SNMP Scanner
title: '[BUG] '
labels: bug
assignees: ''

---

## Description
A clear and concise description of what the bug is.

## Steps to Reproduce
1. Configure scanner via '...'
2. Run SNMP Scanner with parameters/command '...'
3. See error '...'

## Expected Behavior
A clear and concise description of what you expected to happen.

## Environment Details
- **Python Version:** <!-- e.g., 3.9, 3.10 -->
- **Operating System:** <!-- e.g., Debian 11, Centos 8, Ubuntu 22.04 -->
- **SNMP Target Device Model & Firmware:** <!-- e.g., Cisco Catalyst 2960, HP LaserJet Pro -->
- **SNMP Protocol Version:** <!-- e.g., SNMPv1, SNMPv2c, SNMPv3 -->

## Configuration Sample
Provide a relevant snippet of your configuration (e.g., config files or parameters, omitting private SNMP communities or auth credentials).
> [!IMPORTANT]
> Never share SNMPv1/v2c community strings (e.g. public/private) or SNMPv3 authentication keys.

```ini
# Paste your sanitized config file snippet here
```

## Logs & SNMP Debug Output
Please run the scanner in debug mode and paste the logs showing the OID walks or target connection errors.
```text
// Paste log output here
```

## Additional Context
Add any other context about the problem here (e.g. specific MIB files used, network firewall rules).
