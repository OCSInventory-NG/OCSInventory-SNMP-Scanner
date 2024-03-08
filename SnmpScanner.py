import configparser
from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, UsmUserData, usmDESPrivProtocol, usmAesCfb128Protocol
import ipaddress
import json
import logging
import requests
import os

DIR = os.path.dirname(os.path.abspath(__file__))


class SNMPScanner:
    """
    SNMP Scanner class to scan a network for SNMP devices and send the results to OCS.
    Process is as follows:
        - Retrieve SNMP configuration from the server
        - Scan the network based on the configuration
        - Format the scan results to the OCS template
        - Send the formatted results to the server

    The scanner can operate in two modes:
        - ONLINE: The scanner retrieves the SNMP configuration from the server and sends the results to the server
        - OFFLINE: The scanner uses a local configuration and stores the results locally

    To determine which configuration to use, the scanner uses the following order of precedence:
        1. If the configuration applies to the template
        2. If the configuration applies to the subnet
    """
    def __init__(self):
        self.read_config()
        self.log_file = DIR + "/logs/snmp_scanner.log"
        logging.basicConfig(filename=self.log_file, level=self.log_level, format="%(asctime)s - %(levelname)s - %(message)s")
        logging.info("Starting SNMP scanner...")
        # endpoints
        self.auth_endpoint = "/api-auth/token"
        self.config_endpoint = "/config/snmp/"
        self.asset_endpoint = "/asset/bases/"
        self.template_endpoint = "/templates/"
        self.asset_collection_endpoint = "/asset/collection/"
        self.oids = {
            "description": "1.3.6.1.2.1.1.1.0",
            "name": "1.3.6.1.2.1.1.5.0",
            "srcmac": "1.3.6.1.2.1.2.2.1.6.1",
            "serial": "1.3.6.1.2.1.47.1.1.1.1.11.1"
        }
        self.found = {}

    def read_config(self):
        """Read the configuration file using configparser."""
        config = configparser.ConfigParser()
        if not os.path.exists(DIR + '/config/scanner.conf'):
            logging.error("Configuration file not found, exiting...")
            exit()
        else:
            config.read(DIR + '/config/scanner.conf')
            self.auth_data = {
                "username": config.get('auth', 'ocs_user'),
                "password": config.get('auth', 'ocs_password')
            }
            self.base_url = config.get('api', 'ocs_base_url')
            self.mode = config.get('scanner', 'scanner_mode')
            self.inventoy_dir = DIR + config.get('scanner', 'local_inventory_dir')
            self.log_level = config.get('scanner', 'log_level')

    def generate_subnet_ips(self):
        """Generate all IP addresses for the given subnet."""
        network = ipaddress.ip_network(self.subnet)
        return [str(ip) for ip in network.hosts()]

    def get_auth_token(self, auth_data):
        """
        Get the authentication token from OCS
        """
        url = self.base_url + self.auth_endpoint
        payload = {
            "username": auth_data["username"],
            "password": auth_data["password"]
        }
        headers = {
            "Content-Type": "application/json"
        }
        response = requests.post(url, json=payload, headers=headers)

        if response.status_code == 200:
            logging.info("Authentication token retrieved successfully")
            self.token = response.json()["token"]
            return True
        else:
            logging.error(f"Failed to retrieve authentication token: {response.status_code}")
            return False

    def check_server(self):
        """Check if the OCS server is reachable, needs authentication."""
        try:
            isOk = self.get_auth_token(self.auth_data)
            if isOk:
                return True
            else:
                return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to reach server: {e}")
            return False

    def parse_snmp_configuration(self, config):
        """
        Parse the SNMP configuration received from the server

        We are particularly interested in : 
            - enabled - whether SNMP is enabled
            - which templates the configuration applies to
            - which subnets the configuration applies to
        """

        parsed_configs = []

        # first element is the enabled flag
        enabled = config['value'][0]['value']

        if not enabled:
            print("SNMP is not enabled on the server, scan will not be launched")
            exit()

        # Skip the first element (index 0) as it's not part of the configurations
        for config_group in config['value'][1:]:
            # Initialize a template for storing parsed configuration
            config_template = {
                "name": "",
                "version": "",
                "user": "",
                "level": "",
                "password": "",
                "auth_protocol": "",
                "priv_protocol": "",
                "priv_password": "",
                "templates": [],
                "subnets": [],
                "retries": "",
                "timeout": "",
            }

            for item in config_group:
                key = item['name']
                value = item['value']

                # Direct mapping for most fields
                if key in config_template:
                    config_template[key] = value
                elif key == 'templates':
                    # Assuming the value for templates can be directly assigned
                    config_template['templates'] = value if value else []
                elif key == 'subnets':
                    # Ensuring subnets are stored as a list, even if only a single subnet is provided
                    config_template['subnets'] = value if isinstance(value, list) else [value]

            parsed_configs.append(config_template)

        self.generate_ips_for_configs(parsed_configs)
        self.communities = parsed_configs

    def generate_ips_for_configs(self, parsed_configs):
        """Generate the list of IPs for each configuration."""
        for config in parsed_configs:
            config['ips'] = []
            for subnet in config['subnets']:
                network = ipaddress.ip_network(subnet)
                config['ips'] += [str(ip) for ip in network.hosts()]

    def retrieve_snmp_configuration(self):
        """Retrieve SNMP configuration from the server."""
        if self.mode == 'ONLINE':
            url = self.base_url + self.config_endpoint
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Token {self.token}",
            }
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                self.config = response.json()
                logging.info("SNMP configuration retrieved successfully from OCS server")
                self.parse_snmp_configuration(self.config)
                logging.info("SNMP configuration parsed successfully")
            else:
                logging.error(f"Failed to retrieve SNMP configuration: {response.status_code}")


        if self.mode == 'OFFLINE':
            logging.info("Operating in OFFLINE mode. Using local configuration.")
            if os.path.exists(DIR + "/config/communities.json"):
                with open(DIR + "/config/communities.json", "r") as file:
                    self.communities = json.load(file)
                    self.generate_ips_for_configs(self.communities)
                    logging.info("Local SNMP configuration parsed successfully")
            else:
                logging.error("Local SNMP configuration not found, exiting...")
                exit()

    def snmpv1_scan(self, community, ip, oid):
        """Scan the network for SNMPv1 devices."""
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community['name'], mpModel=0),
                UdpTransportTarget((ip, 161), timeout=community['timeout'], retries=community['retries']),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
        )

        return errorIndication, errorStatus, errorIndex, varBinds
    
    def snmpv2c_scan(self, community, ip, oid):
        """Scan the network for SNMPv2c devices."""
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community['name'], mpModel=1),
                UdpTransportTarget((ip, 161), timeout=community['timeout'], retries=community['retries']),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
        )

        return errorIndication, errorStatus, errorIndex, varBinds

    def snmpv3_scan(self, community, ip, oid):
        """Scan the network for SNMPv3 devices."""
        authProtocol = None
        privProtocol = None
        if community['priv_protocol'] == 'DES':
            privProtocol = usmDESPrivProtocol
        elif community['priv_protocol'] == 'AES':
            privProtocol = usmAesCfb128Protocol

        if community['level'] == 'authNoPriv':
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(
                    SnmpEngine(),
                    UsmUserData(community['user'], authKey=community['password'], authProtocol=authProtocol),
                    UdpTransportTarget((ip, 161), timeout=community['timeout'], retries=community['retries']),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                )
            )
        elif community['level'] == 'authPriv':
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(
                    SnmpEngine(),
                    UsmUserData(community['user'], authKey=community['password'], privKey=community['priv_password'], authProtocol=authProtocol, privProtocol=privProtocol),
                    UdpTransportTarget((ip, 161), timeout=community['timeout'], retries=community['retries']),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                )
            )

        return errorIndication, errorStatus, errorIndex, varBinds


    def scan_network(self):
        """Scan the network for SNMP devices, based on fixed OIDs."""
        results = {}
        logging.info("Starting network scan...")
        for community in self.communities:
            self.found[community['name']] = 0
            for ip in community['ips']:
                logging.debug(f"======== Scanning {ip} with community '{community['name']}' ========")
                device_results = {}
                for name, oid in self.oids.items():
                    logging.debug(f"Getting OID {oid}...")
                    if community['version'] == '2c':
                        errorIndication, errorStatus, errorIndex, varBinds = self.snmpv2c_scan(community, ip, oid)
                    elif community['version'] == '1':
                        errorIndication, errorStatus, errorIndex, varBinds = self.snmpv1_scan(community, ip, oid)
                    elif community['version'] == '3':
                        errorIndication, errorStatus, errorIndex, varBinds = self.snmpv3_scan(community, ip, oid)

                    if errorIndication:
                        logging.debug(f"Error: {errorIndication}")
                    elif errorStatus:
                        logging.debug(f"Error: {errorStatus.prettyPrint()}")
                    else:
                        for varBind in varBinds:
                            logging.debug(f"OID: {oid} - {varBind.prettyPrint()}")
                            device_results[name] = varBind.prettyPrint().split('=')[1].strip()
                        results[ip] = device_results
                self.found[community['name']] += 1
                        
        return results

    def advanced_scan(self):
        """Perform advanced scans based on the templates."""
        advanced_results = {}
        template_oids = {}
        logging.info("Starting advanced scan based on templates...")
        # check if the template is indeed an SNMP template and get the OIDs
        for result in self.formatted_results:
            if result["template"] and result["template"]["os"] == "SNMP":
                template_oids[result["srcip"]] = self.decompose_template(result["template"])
            # get rid of the template key (result is what we want to send to the server)
            result.pop("template")

        for community in self.communities:
            for ip in community['ips']:
                logging.debug(f"======== Advance scanning {ip} with community '{community['name']}' ========")
                device_results = {}
                if ip in template_oids:
                    for section_name, section in template_oids[ip].items():
                        for name, oid in section.items():
                            logging.debug(f"Getting OID {oid}...")
                            if community['version'] == '2c':
                                errorIndication, errorStatus, errorIndex, varBinds = self.snmpv2c_scan(community, ip, oid)
                            elif community['version'] == '1':
                                errorIndication, errorStatus, errorIndex, varBinds = self.snmpv1_scan(community, ip, oid)
                            elif community['version'] == '3':
                                errorIndication, errorStatus, errorIndex, varBinds = self.snmpv3_scan(community, ip, oid)

                            if errorIndication:
                                logging.error(f"Error: {errorIndication}")
                            elif errorStatus:
                                logging.error(f"Error: {errorStatus.prettyPrint()}")
                            else:
                                for varBind in varBinds:
                                    logging.debug(f"OID: {oid} - {varBind.prettyPrint()}")
                                    # get only the value of the oid
                                    value = varBind.prettyPrint().split('=')[1].strip()
                                    # if same section name already exists, add the new value to it
                                    if section_name in device_results:
                                        device_results[section_name][0][name] = value
                                    else:
                                        device_results[section_name] = [{name: value}]
                                advanced_results[ip] = device_results

        self.format_to_template(advanced_results)

        return advanced_results

    def decompose_template(self, data):
        # decomposed structure
        decomposed = {}
        for section in data['sections']:
            section_dict = {}
            for field in section['fields']:
                # map the field name to its retrieval value
                section_dict[field['name']] = field['retrival_value']

            decomposed[section['name']] = section_dict

        return decomposed

    def send_to_ocs(self):
        """Send formatted data to the server."""
        logging.info("Sending data to OCS...")
        if self.mode == 'ONLINE':
            url = self.base_url + self.asset_collection_endpoint
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Token {self.token}",
            }
            for device in self.formatted_results:
                method = device.pop("method")
                if method == "PUT":
                    response = requests.put(url, json=device, headers=headers)
                    logging.debug(f"PUTing device : {device}")
                elif method == "POST":
                    response = requests.post(url, json=device, headers=headers)
                    logging.debug(f"POSTing device : {device}")

                if response.status_code in [200, 201]:
                    logging.info(f"Device {device['uuid']} created/updated successfully")
                elif response.status_code not in [200, 201]:
                    logging.error(f"Failed to create/update device {device['uuid']}: {response.status_code}")

        else:
            logging.info(f"Server is not reachable. Storing inventories locally and writing logs to {self.log_file}")
            self.store_data_locally(self.formatted_results)

    def store_data_locally(self, data):
        """Store inventories locally, naming the files with the device's uuid."""
        if os.path.exists(self.inventoy_dir):
            for file in os.listdir(self.inventoy_dir):
                # remove all files in the directory
                os.remove(self.inventoy_dir + "/" + file)
                
            for device in data:
                filename = "/" + device['uuid'] + ".json"
                with open(self.inventoy_dir + filename, "w") as file:
                    json.dump(device, file)
                    logging.info(f"Device {device['uuid']} stored locally")
        else:
            logging.error(f"Local inventory directory {self.inventoy_dir} not found, exiting...")
            exit()

    def format_to_base(self, results):
        """
        Format the scan results according to the base template.
        """
        formatted_results = []

        #  asset base 
        base_template = {
            "name": "",
            "description": "",
            "serial": "TEST",
            "osname": "SNMP",
            "osversion": "TEST",
            "uuid": "",
            "srcip": "",
            "srcmac": "TEST",
            "domain": "TEST",
        }

        for ip, device_results in results.items():
            device_template = base_template.copy()
            device_template["srcip"] = ip
            
            # map SNMP results to template fields
            for name, value in device_results.items():
                if name in device_template:
                    # and value isnt empty string or null or None
                    if value:
                        device_template[name] = value

            if not device_template["uuid"]:
                device_template["uuid"] = device_template["name"] + "-" + device_template["srcip"]

            formatted_results.append(device_template)

        return formatted_results

    def format_to_template(self, advanced_results):
        """Merge the advanced results with the formatted results for template inventory."""
        # add the template_inventory key to the formatted results dictionary
        for result in self.formatted_results:
            if result["srcip"] in advanced_results:
                result["template_inventory"] = advanced_results[result["srcip"]]

    def get_templates(self):
        """Retrieve the available templates from the server."""
        asset_url = self.base_url + self.asset_endpoint + "?uuid="
        template_url = self.base_url + self.template_endpoint
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Token " + self.token,
        }

        for result in self.formatted_results:
            # check if the device exists already
            url = asset_url + result["uuid"]
            response = requests.get(url, headers=headers)
            if response.status_code == 200 and response.json():
                existing_asset = response.json()[0]
                # if a template has been assigned
                if existing_asset.get('template'):
                    url = template_url + str(existing_asset['template'])
                    response = requests.get(url, headers=headers)
                    if response.status_code == 200:
                        result["template"] = response.json()
                        result["method"] = "PUT"
                    else:
                        logging.error(f"Failed to retrieve template: {response.status_code}")
                        result["template"] = None
                        result["method"] = "PUT"
                else:
                    logging.info(f"No template assigned to {result['uuid']}")
                    result["template"] = None
                    result["method"] = "POST"
            else:
                logging.info(f"Device {result['uuid']} not found, creating new entry...")
                result["template"] = None
                result["method"] = "POST"

    def run(self):
        """Main method to run the scanner."""
        # if the scanner is in ONLINE mode and the server is not reachable, switch to OFFLINE mode
        if self.mode == 'ONLINE' and not self.check_server():
            logging.error("Server is not reachable, switching to OFFLINE mode...")
            self.mode = 'OFFLINE'
            
        self.retrieve_snmp_configuration()
        # base scan
        scan_results = self.scan_network()
        self.formatted_results = self.format_to_base(scan_results)

        if self.mode == 'ONLINE':
            # associate formatted results with their appropriate templates, based on their uuid
            self.get_templates()
            # perform advanced scans based on templates
            self.advanced_results = self.advanced_scan()
            # sending inventory to OCS
            self.send_to_ocs()
            logging.info(f"Scan complete. Found a total of {len(self.formatted_results)} devices")
        elif self.mode == 'OFFLINE':
            self.store_data_locally(self.formatted_results)
            logging.info(f"Inventories stored locally in {self.inventoy_dir}. Scan complete. Found a total of {len(self.formatted_results)} devices.")


if __name__ == "__main__":
    scanner = SNMPScanner()
    scanner.run()
