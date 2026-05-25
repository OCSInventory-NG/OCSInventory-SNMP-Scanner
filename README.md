# OCS SNMP Scanner

## Overview
The SNMP Scanner is a tool designed to scan networks and collect device information using the SNMP protocol. The scanner always uses an hardcoded base template (and matching generic OIDs) to retrieve information from the devices, and if available, performs an additional scan using a custom template retrieved from the OCS server.

### Modes
The scanner can operate in two modes: `online` and `offline`.
#### Online
In `online` mode, the scanner queries the OCS server to check whether or not the device has already been scanned and if so, checks if a template has been defined for it. If a template is available, the scanner performs an advanced scan using the custom template. The scanner then sends the inventory data to the server.
> Note : If the scanner is unable to get/send data to the OCS server, it will switch to `offline` mode automatically. Inventory data will be stored in individual files in the `local_inventory_dir` directory and local configuration will be used.

#### Offline
In `offline` mode, the scanner only uses the base template and does not query the OCS server at all, storing the inventory data in individual files at the end of the scan.

### Scanning
#### Supported SNMP versions
The scanner supports SNMPv1, SNMPv2c and SNMPv3. The version to use is either specified in the configuration file 'configs.json' or in the configurations retrieved from the OCS server.

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
- View : `Inventory - Asset`, `Templates`, `SNMP Scanner`, `Configuration - General`, `SNMP Communities`
- Add : `Inventory - Asset`, `SNMP Scanner`
- Change : `Inventory - Asset`, `SNMP Scanner`
- Delete : `Inventory - Asset`

#### SNMP configuration (mandatory)
SNMP must be enabled on the OCS server and at least one SNMP configuration must be defined. Within a configuration, targeted subnets need to be defined. Configuration contains the following fields:
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
- Subnets : list of subnets to scan, in CIDR notation. These will be matched against the Scanner's `subnets` field to determine if the scanner should use this configuration to scan a device

> Configurations need to be assigned to the scanner in  OCS web interface. The scanner will use the `subnets` field to determine which configuration to use to scan which device.


#### Scanner registration (automatic when using the `online` mode, optional when using the `offline` mode)
Registration of the scanner is done automatically when using the `online` mode. The scanner will create its own instance in the OCS server's database during its first run. The entry will be created using the `name` and `subnets` set in the local configuration file. The `name` is a unique name for the scanner and the `subnets` is a list of subnets to scan. 

Once registered, you will **need to assign SNMP configurations** (see previous step) to the scanner using the OCS server's web interface. The configurations will be used to scan the devices in the targeted subnets.

The scanner will also update its entry in the database at the end of each run, updating the `last_updated` and `last_scan` fields, as well as totals of scanned and found devices.

Please note : Configuration retrieved for the scanner from the OCS server will override the local configuration file. If you wish to run the scanner with its local configuration, switch to `offline` mode for a debug run or update the configuration on the OCS server.


#### SNMP templates (optional)
Custom templates can be defined for specific devices in the OCS server's web interface. The templates are used to perform an advanced scan of the devices, using specific OIDs to retrieve specific information. The templates are defined in the OCS server's web interface and can be affected to specific devices using `Rules`. The scanner will retrieve the template for a device if one is available and perform an advanced scan using the OIDs defined in the template.

For template examples and instructions regarding building your own template, please refer to the [SNMP Template Creation](#SNMP-Template-Creation) section.


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
5. If using the `offline` mode, edit the `config/configs.json` file to match your SNMP configurations

The `configs.json` JSON file contains the SNMP configurations for the scanner. Refer to the [SNMP Configuration](#SNMP-configuration-(mandatory)) section for more information on the mandatory fields. By default, the file also contains default configurations that you can copy and modify. Multiple communities can be defined in the file, the scanner will use the `subnets` field to determine which community to use to scan a device. 
> Tip : the `/snmp/config/` API endpoint can be used to retrieve existing SNMP configurations from the OCS server and update the `configs.json` file.

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
	- `name` : the unique name of the scanner. This field will be used to identify the scanner in the OCS server's database. Not used in `offline` mode
  - `mibs_dir` : the MIB directory path
  - `server_logging_enabled` : enable server logging or not. Not used in `offline` mode
  - `server_log_level`: server log level (INFO, DEBUG, WARNING, ERROR, CRITICAL)


#### Running the scanner
Run the scanner using the following command:
```bash
python SnmpScanner.py
```

The first run will create the scanner's instance in the OCS server's database.

Make sure SNMP configurations are assigned to the scanner in the OCS server's web interface, otherwise the scanner will not be able to scan any devices.

#### Results for online mode
The scanner will output the results of the scan to the log file, as well as write them to the OCS server's database. The results will be available in the OCS server's web interface under the `Inventory` tab.

#### Results for offline mode
The scanner will output the results of the scan to the console, as well as write them to individual files in the `local_inventory_dir` directory. The files will be named after the device's UUID and contain the inventory data in JSON format.
The contents of these files can be used as is to inject the inventory data into the OCS server's database using the API (POST /asset/collection/).

## Interactions
This section describes the interactions between the scanner and the OCS server, and the scanner and the devices to be scanned. It is meant to provide a broad overview of what requests are made to the server and the devices, and what responses are expected.

### Assets
SNMP assets are scanned using the pysnmp library.
The scan is done in two steps:
1. A basic scan is performed using a hardcoded base template and generic OIDs
2. If a custom template is available for the device, an advanced scan is performed using the custom template

### Local files
In `offline` mode, the scanner stores the inventory data in individual files at the end of the scan. The files are named after the device's UUID and contain the inventory data in JSON format.
The scanner reads its configuration from a file named `scanner.conf` located in the `config` directory. 
SNMP configurations are read from a file named `configs.json` located in the same directory.
Logs are written to a file named `snmp_scanner.log` located in the `logs` directory.

## SNMP Template Creation
### SNMP template example:
NB : OIDs and names may not be relevant, this is just an example.
```json
{
  "name": "SNMP_DEV",
  "os": "SNMP",
  "sections": [
    {
      "name": "INFORMATION",
      "retrieval_method": "SNMP_GET",
      "retrieval_output": "JSON",
      "target": "SNMP",
      "fields": [
        {
          "name": "Location",
          "retrieval_value": "1.3.6.1.2.1.1.6.0",
          "override_target": false,
          "new_target": null,
          "retrieval_method": null,
          "retrieval_output": null
        },
				{
          "name": "sysUptime",
          "retrieval_value": "1.3.6.1.2.1.1.3.0",
          "override_target": false,
          "new_target": null,
          "retrieval_method": null,
          "retrieval_output": null
        }
      ],
      "options": {
        "need_format": false
      }
    }
  ]
}
```

### SNMP retrieval methods
Two methods can be used to retrieved data from OIDs:
- SNMP WALK : Starting from a given OID, walk the SNMP tree and retrieve a list of data
- SNMP GET : Get the value corresponding to the given OID

In our template case, the `retrieval_method` field is used to specify the method to use in the template section. If set to `SNMP_WALK`, the scanner will walk the SNMP tree starting from the `retrieval_value` OID and retrieve the data, for all the fields in the section. If set to `SNMP_GET`, the scanner will retrieve the value corresponding to the `retrieval_value` OID for each field in the section.

In terms of output, this means that SNMP_WALK will output a list of items for a section, where SNMP_GET will output only one item. 
In the example above, the INFORMATION section is set to use the SNMP_GET method, and the other two sections are set to use SNMP_WALK. 


#### SNMP_WALK mode
Starting from a given OID, walk the SNMP tree and retrieve a list of data
> For this mode to work, we expect the OIDs used in a same section to belong to the same SNMP node and have the same indexes. In practice, this means that the indexes from the first OID being walked will be used for the rest of the fields. 

#### SNMP_GET mode
Get the value corresponding to the given OID