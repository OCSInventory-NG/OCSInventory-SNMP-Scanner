# OCS SNMP Scanner

## Overview
The SNMP Scanner is a tool designed to scan networks and collect device information using the SNMP protocol. The scanner always uses an hardcoded base template (and matching generic OIDs) to retrieve information from the devices, and if available, performs an additional scan using a custom template retrieved from the OCS server.

### Modes
The scanner can operate in two modes: `online` and `offline`.
#### Online
In `online` mode, the scanner queries the OCS server to check whether or not the device has already been scanned and if so, checks if a template has been defined for it. If a template is available, the scanner performs an advanced scan using the custom template. The scanner then sends the inventory data to the server.
> Note : In `online` mode, if the scanner cannot reach the OCS server or authenticate on it, it logs an error and stops. Every error that stops the scanner gives exit code `1`. To scan with the local configuration and store inventories in `local_inventory_dir`, use the `offline` mode.

#### Offline
In `offline` mode, the scanner only uses the base template and does not query the OCS server at all, storing the inventory data in individual files at the end of the scan.

### Scanning
#### Supported SNMP versions
The scanner supports SNMPv1, SNMPv2c and SNMPv3. The version to use is either specified in the configuration file 'configs.json' or in the configurations retrieved from the OCS server.

#### Basic scan
The basic scan is performed using a hardcoded base template corresponding to the InventoryBase model fields. The scanner purposefully uses generic OIDs to populate the fields, as the goal is to retrieve as much information as possible from the devices, regardless of their type. The basic scan is performed for all devices, regardless of whether or not a custom template is available for them.

No generic OID holds a serial number on every device, so the scanner walks ENTITY-MIB `entPhysicalSerialNum` (`1.3.6.1.2.1.47.1.1.1.1.11`), then Printer-MIB `prtGeneralSerialNumber` (`1.3.6.1.2.1.43.5.1.1.17`), and keeps the first non-empty value. If neither returns one, the serial is set to `Empty`, the value the OCS server already stores for agents without a serial number. The OIDs of the `serial_oids` setting are walked before these two. A device without a sysName is named after its IP, a sysName longer than 50 characters is truncated (the longest name the OCS server accepts).

#### Advanced scan
If a custom template is available for a device, the scanner performs an advanced scan using the custom template. The custom template is retrieved from the OCS server and contains a list of OIDs (fields) regrouped in sections. The scanner uses the OIDs to retrieve the corresponding values from the devices and populates the fields with the values.


## Prerequisites
### System
- Python 3.9 or later
- `pip` package manager

### Python
See `requirements.txt` for the authoritative list and version bounds:
- `pysnmp` (>= 7.1.6, < 8)
- `cryptography` (>= 47), for SNMPv3 privacy (DES, AES)
- `pysmi` (>= 1.6.2)
- `requests`

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
- Subnets : list of subnets to scan, in CIDR notation. A scanner uses the configuration on the addresses that are both in these subnets and in its own `subnets` field: a configuration on `10.0.0.0/16` assigned to a scanner on `10.0.1.0/24` scans `10.0.1.0/24`, and the other way round. Invalid subnets, such as `192.168.1.1/24` (host bits set), are skipped with a warning

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
4. Create your configuration files from the shipped samples:
```bash
cp config/scanner.conf-sample config/scanner.conf
cp config/configs.json-sample config/configs.json
```
5. Edit the `config/scanner.conf` file to match your environment, see below for more information
6. If using the `offline` mode, edit the `config/configs.json` file to match your SNMP configurations

> When installing from the `.deb`/`.rpm` packages, both files live in `/etc/ocsinventory-snmp-scanner/` and `config/` is a symlink to that directory.

The `configs.json` JSON file contains the SNMP configurations for the scanner. Refer to the [SNMP Configuration](#SNMP-configuration-(mandatory)) section for more information on the mandatory fields. By default, the file also contains default configurations that you can copy and modify. Multiple communities can be defined in the file, the scanner will use the `subnets` field to determine which community to use to scan a device. 
> Tip : the `/snmp/config/` API endpoint can be used to retrieve existing SNMP configurations from the OCS server and update the `configs.json` file.

#### Configuration
The `scanner.conf` file contains the following sections and fields:
- `[auth]`: contains the authentication information for the OCS server
	- `ocs_user` : the username of the SNMP user to authenticate with
	- `ocs_password` : the password of the SNMP user to authenticate with
- `[api]` : contains the API endpoint information for the OCS server
	- `ocs_base_url` : the URL of the OCS server
	- `certificate` : path to a PEM certificate file, used in addition to the system trust store. Leave empty to rely on the system trust store alone. See [HTTPS and certificates](#https-and-certificates)
	- `bypass_certificate` : set to `true` to skip certificate validation entirely (insecure, default `false`)
- `[scanner]` : contains the scanner information
	- `scanner_mode` : the mode to run the scanner in (`ONLINE` or `OFFLINE`)
	- `local_inventory_dir` : the directory to store the inventory data in when running in `offline` mode
	- `targeted_subnets` : the subnets to scan, separated by commas no spaces, used in `offline` mode
	- `max_concurrent_devices` : the maximum number of devices queried at the same time (default `50`, `1` queries one device at a time). When the key is absent, or its value is not an integer of at least `1`, the default is used; an invalid value is also reported as a warning in the log. The value in use is logged at startup: `Scan concurrency: up to 50 devices at a time`
	- `log_level` : the log level to use (INFO, DEBUG, WARNING, ERROR, CRITICAL)
	- `name` : the unique name of the scanner. This field will be used to identify the scanner in the OCS server's database. Not used in `offline` mode
  - `mibs_dir` : the directory of your custom MIBs. See [Custom MIBs](#custom-mibs)
  - `serial_oids` : OIDs walked for the serial number before ENTITY-MIB and Printer-MIB, in this order, separated by commas (optional). The first non-empty value wins. Give the OID of the object (`1.3.6.1.4.1.9.3.6.3`) or of its instance (`1.3.6.1.4.1.9.3.6.3.0`). Invalid entries are skipped with a warning
  - `server_logging_enabled` : enable server logging or not. Not used in `offline` mode
  - `server_log_level`: server log level (INFO, DEBUG, WARNING, ERROR, CRITICAL)


#### HTTPS and certificates

If your OCS server is reached over `http://`, none of this applies and no certificate is needed.

Over `https://`, the scanner validates the server certificate against the **system trust store**, so a CA deployed with `update-ca-certificates` (or the distribution equivalent) is enough and no configuration is needed.

Set `certificate` to a PEM file when the certificate cannot be validated that way, typically a private CA or a self-signed certificate that is not installed system-wide. The system store is still tried first, the file is only used as a fallback, so it adds to the trusted roots rather than replacing them.

```ini
[api]
ocs_base_url = https://ocs.example.com
certificate = /etc/ssl/certs/ocs-ca.pem
bypass_certificate = false
```

As a last resort, `bypass_certificate = true` disables validation altogether. This applies to **all** scanner traffic, credentials included, and should be limited to self-signed lab setups.

The scanner states which mode is active at startup:
```
Certificate mode: TLS enabled (system store), fallback certificate path available: /etc/ssl/certs/ocs-ca.pem
```

#### Custom MIBs

Put the MIB files of your devices in `mibs_dir`, subdirectories included. File names do not matter: each module is found by the name declared in its file (`ACME-MIB DEFINITIONS ::= BEGIN`), and files that declare none are ignored.

The values of the objects defined in these MIBs, and in the MIBs they import, are formatted according to their definition: enumerations by name (`up` instead of `1`), object identifiers by name (`ACME-MIB::acmeSwitch24`), strings by their display hint (MAC addresses for example). The OIDs of the templates stay numeric.

The modules a MIB imports are looked up in `mibs_dir` first, then in `/usr/share/snmp/mibs` and `/usr/share/mibs`, where distributions install the standard MIBs (`snmp-mibs-downloader` package on Debian and Ubuntu).

MIBs are compiled at startup into `~/.pysnmp/mibs` of the user running the scanner (`/var/lib/ocsinventory-snmp-scanner/.pysnmp/mibs` with the packages), and compiled again only when their file changes. A MIB that cannot be compiled or loaded is reported in the log with its file and the reason, for example a missing import; the other MIBs are loaded anyway. The startup log lists the modules loaded:
```
2 MIB modules loaded from /var/lib/ocsinventory-snmp-scanner/mibs: ACME-SMI, ACME-MIB
```


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
> For this mode to work, the OIDs of a same section must be columns of the same SNMP table. Values are matched by their index, the end of their OID after the field's OID: each index gives one item, and a field without a value for an index is left out of that item. 

#### SNMP_GET mode
Get the value corresponding to the given OID