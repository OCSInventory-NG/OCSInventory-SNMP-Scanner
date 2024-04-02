# OCS SNMP Scanner

## Overview
The SNMP Scanner is a tool that allows to scan a network for devices and retrieve information about them using the SNMP protocol. The scanner always uses an hardcoded base template (and matching generic OIDs) to retrieve information from the devices, and if available, performs an additional scan using a custom template retrieved from the OCS server.

### Modes
The scanner can operate in two modes: `online` and `offline`.
#### Online
In `online` mode, the scanner queries the OCS server to check whether or not the device has already been scanned and if so, checks if a template has been defined for it. If a template is available, the scanner performs an advanced scan using the custom template. The scanner then sends the inventory data to the server.
> Note : If the scanner is unable to get/send data to the OCS server, it will switch to `offline` mode automatically. Inventory data will be stored in individual files in the `local_inventory_dir` directory and local configuration will be used.

#### Offline
In `offline` mode, the scanner only uses the base template and does not query the OCS server at all, storing the inventory data in individual files at the end of the scan.

### Scanning
#### Supported SNMP versions
The scanner supports SNMPv1, SNMPv2c and SNMPv3. The version to use is either specified in the configuration file 'communities.json' or in the configurations retrieved from the OCS server.

#### Basic scan
The basic scan is performed using a hardcoded base template corresponding to the InventoryBase model fields. The scanner purposefully uses generic OIDs to populate the fields, as the goal is to retrieve as much information as possible from the devices, regardless of their type. The basic scan is performed for all devices, regardless of whether or not a custom template is available for them.

#### Advanced scan
If a custom template is available for a device, the scanner performs an advanced scan using the custom template. The custom template is retrieved from the OCS server and contains a list of OIDs (fields) regrouped in sections. The scanner uses the OIDs to retrieve the corresponding values from the devices and populates the fields with the values.


## Prerequisites
### System
- Python 3.6 or later
- `pip` package manager

### Python
- `pysnmp` library
- `requests` library
- `configparser` library
- `socket` library

### OCS Configuration
In the `online` mode the scanner requires specific configuration on the OCS server, see below.

#### User creation (mandatory)
A dedicated user must be created on the OCS server with appropriate permissions to query the API. The user must be created in the OCS server's web interface and must have the following permissions:
- View : `Inventory - Asset`, `Templates`, `SNMP Scanner`, `Configuration - General`
- Add : `Inventory - Asset`, `SNMP Scanner`
- Change : `Inventory - Asset`, `SNMP Scanner`
- Delete : `Inventory - Asset`

#### SNMP configuration (mandatory)
SNMP must be enabled on the OCS server and at least one community must be defined. Within a community, targeted subnets can be defined. Configuration for one community is as follows:
- Name : name of the community
- Version : SNMP version to use (v1, v2c or v3)
- User : SNMP user to use (only for SNMPv3)
- Password : SNMP password to use (only for SNMPv3)
- Level : Authentication level to use (only for SNMPv3)
- Authentication protocol : Authentication protocol to use (only for SNMPv3)
- Privacy protocol : Privacy protocol to use (only for SNMPv3)
- Privacy password : Privacy password to use (only for SNMPv3)
- Retries : number of retries to perform when scanning a device
- Timeout : timeout in seconds to wait for a response from a device
- Subnets : list of subnets to scan, in CIDR notation. These will be matched against the Scanner's `subnets` field to determine if the scanner should use the community to scan a device


#### Scanner registration (automatic when using the `online` mode, optional when using the `offline` mode)
Registration of the scanner is done automatically when using the `online` mode. The scanner will create its own instance in the OCS server's database during its first run. The entry will be created using the `identifier` and `subnets` set in the local configuration file. The `identifier` is a unique name for the scanner and the `subnets` is a list of subnets to scan. The scanner will also update its entry in the database at the end of each run, updating the `last_updated` and `last_scan` fields, as well as totals of scanned and found devices.

Please note : Configuration retrieved for the scanner from the OCS server will override the local configuration file. If you wish to run the scanner with its local configuration, switch to `offline` mode for a debug run or update the configuration on the OCS server.


#### SNMP templates (optional)
Custom templates can be defined for specific devices in the OCS server's web interface. The templates are used to perform an advanced scan of the devices, using specific OIDs to retrieve specific information. The templates are defined in the OCS server's web interface and can be affected to specific devices using `Rules`. The scanner will retrieve the template for a device if one is available and perform an advanced scan using the OIDs defined in the template.



## Installation and Configuration
### ONLINE Scanner installation and configuration
#### Installation
1. Clone the repository
2. Navigate to the `SnmpScanner` directory
3. Install the required packages using `pip`:
```bash
pip install -r requirements.txt
```
4. Edit the `config/scanner.conf` file to match your environment, see below for more information

#### Configuration
The `scanner.conf` file contains the following sections and fields:
- `[auth]`: contains the authentication information for the OCS server
	- `ocs_user` : the username of the SNMP user to authenticate with
	- `ocs_password` : the password of the SNMP user to authenticate with
- `[api]` : contains the API endpoint information for the OCS server
	- `ocs_base_url` : the URL of the OCS server
- `[scanner]` : contains the scanner information
	- `scanner_mode` : the mode to run the scanner in (`ONLINE` or `OFFLINE`)
	- `local_inventory_dir` : the directory to store the inventory data in when running in `offline` mode
	- `targeted_subnets` : the subnets to scan, separated by commas no spaces, used in `offline` mode
	- `log_level` : the log level to use (INFO, DEBUG, WARNING, ERROR, CRITICAL)
	- `identifier` : the unique name of the scanner. This field will be used to identify the scanner in the OCS server's database. Not used in `offline` mode

#### Running the scanner
TODO : depends on how the module will run (service, cron job, etc.).
At the moment, run the scanner using the following command:
```bash
python SnmpScanner.py
```

#### Results
The scanner will output the results of the scan to the console, as well as write them to the OCS server's database. The results will be available in the OCS server's web interface under the `Inventory` tab.

### OFFLINE Scanner installation and configuration
#### Installation
1. Clone the repository
2. Navigate to the `SnmpScanner` directory
3. Install the required packages using `pip`:
```bash
pip install -r requirements.txt
```
4. Edit the `config/scanner.conf` file to match your environment
5. If using the `offline` mode, edit the `config/communities.json` file to match your SNMP configurations

#### Configuration
The `scanner.conf` file contains the following sections and fields:
- [auth] : contains the authentication information for the OCS server
	- `ocs_user` : the username of the SNMP user to authenticate with, not used in `offline` mode
	- `ocs_password` : the password of the SNMP user to authenticate with, not used in `offline` mode
- [api] : contains the API endpoint information for the OCS server
	- `ocs_base_url` : the URL of the OCS server, not used in `offline` mode
- [scanner] : contains the scanner information
	- `scanner_mode` : the mode to run the scanner in (`ONLINE` or `OFFLINE`)
	- `local_inventory_dir` : the directory to store the inventory data in when running in `offline` mode
	- `targeted_subnets` : the subnets to scan, separated by commas no spaces, used in `offline` mode
	- `log_level` : the log level to use (INFO, DEBUG, WARNING, ERROR, CRITICAL)
	- `identifier` : the unique name of the scanner. This field will be used to identify the scanner in the OCS server's database. Not used in `offline` mode

The `communities.json` JSON file contains the SNMP configurations for the scanner, it contains a list of communities. Refer to the [SNMP Configuration](#SNMP-configuration-(mandatory)) section for more information on the mandatory fields. By default, the file also contains default configurations that you can copy and modify. Multiple communities can be defined in the file, the scanner will use the `subnets` field to determine which community to use to scan a device.

#### Running the scanner
TODO : depends on how the module will run (service, cron job, etc.).
At the moment, run the scanner using the following command:
```bash
python SnmpScanner.py
```

#### Results
The scanner will output the results of the scan to the console, as well as write them to individual files in the `local_inventory_dir` directory. The files will be named after the device's UUID and contain the inventory data in JSON format.
The contents of these files can be used as is to inject the inventory data into the OCS server's database using the API (POST /asset/collection/).

## Interactions
This section describes the interactions between the scanner and the OCS server, and the scanner and the devices to be scanned. It is meant to provide a broad overview of what requests are made to the server and the devices, and what responses are expected.
### Server endpoints
In execution order, the scanner interacts with the OCS server as follows:
1. `POST /api-auth/token` : to authenticate the SNMP user and retrieve a token
2. `GET /config/snmp/` : to retrieve the SNMP configurations
3. `GET /snmp/scanner/?name=SuperScanner` : checks if the scanner is already registered and retrieves its details if so
4. `GET /asset/bases/?uuid=MyPrinter-1234` : checks if each responding device has already been scanned, triggers the following requests to retrieve the template if so `GET /templates/7`
5. `POST/PUT /asset/collection/` : sends the inventory data to the server for each device

### Assets
SNMP assets are scanned using the pysnmp library.
The scan is done in two steps:
1. A basic scan is performed using a hardcoded base template and generic OIDs
2. If a custom template is available for the device, an advanced scan is performed using the custom template

### Local files
In `offline` mode, the scanner stores the inventory data in individual files at the end of the scan. The files are named after the device's UUID and contain the inventory data in JSON format.
The scanner reads its configuration from a file named `scanner.conf` located in the `config` directory. 
SNMP configurations are read from a file named `communities.json` located in the same directory.
Logs are written to a file named `snmp_scanner.log` located in the `logs` directory.

## Example
### SNMP template :
NB : OIDs and names may not be relevant, this is just an example.
```json
	{
		"name": "SNMP_TEST",
		"os": "SNMP",
		"last_update": "2024-03-06T14:52:16.418214Z",
		"sections": [
			{
				"name": "FIRMWARE",
				"retrival_method": "OID",
				"retrival_output": "JSON",
				"target": "SNMP",
				"fields": [
					{
						"name": "Location",
						"retrival_value": "1.3.6.1.2.1.1.6.0",
						"override_target": false,
						"new_target": null,
						"retrival_method": null,
						"retrival_output": null,
						"options": null
					},
					{
						"name": "sysUptime",
						"retrival_value": "1.3.6.1.2.1.1.3.0",
						"override_target": false,
						"new_target": null,
						"retrival_method": null,
						"retrival_output": null,
						"options": null
					}
				],
				"options": {
					"need_format": false
				}
			},
			{
				"name": "HARDWARE",
				"retrival_method": "OID",
				"retrival_output": "JSON",
				"target": "SNMP",
				"fields": [
					{
						"name": "une adresse mail ?",
						"retrival_value": "1.3.6.1.2.1.1.4.0",
						"override_target": false,
						"new_target": null,
						"retrival_method": null,
						"retrival_output": null,
						"options": null
					},
					{
						"name": "mac",
						"retrival_value": "1.3.6.1.2.1.2.2.1.6.1",
						"override_target": false,
						"new_target": null,
						"retrival_method": null,
						"retrival_output": null,
						"options": null
					}
				],
				"options": {
					"need_format": false
				}
			}
		]
	}
```