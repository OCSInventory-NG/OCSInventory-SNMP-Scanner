# OCS SNMP Scanner

## Overview
The SNMP Scanner is a tool that allows to scan a network for devices and retrieve information about them using the SNMP protocol. The scanner always uses an hardcoded base template (and matching generic OIDs) to retrieve information from the devices, and if available, performs an additional scan using a custom template retrieved from the OCS server.
The scanner can operate in two modes: `online` and `offline`. In `online` mode, the scanner queries the OCS server to check whether or not the device has already been scanned and if so, checks if a template has been defined for it. In `offline` mode, the scanner only uses the base template and does not query the OCS server at all, storing the inventory data in individual files at the end of the scan.


## Prerequisites
### System
- Python 3.6 or later
- `pip` package manager

### Python
- `pysnmp` library
- `requests` library
- `configparser` library

### OCS Configuration
For the `online` mode:
- OCS server must be reachable from the scanner
- A dedicated user must be created on the OCS server with appropriate permissions to query the API (see endpoints listed in the SnmpScanner class)
- SNMP must be enabled on the OCS server
- Communities must be defined for the devices to be scanned. Within a community, targeted subnets must be defined too. 
- 

## Installation


## Process
### Modes

### Scanning


## Interactions
### Server endpoints

### Assets

### Local files