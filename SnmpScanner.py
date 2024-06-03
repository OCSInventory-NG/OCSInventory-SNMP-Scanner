import configparser
from datetime import datetime
import socket
from pysnmp.hlapi import *
import ipaddress
import json
import logging
import requests
import os
import uuid

DIR = os.path.dirname(os.path.abspath(__file__))


class SNMPScanner:
    """
    SNMP Scanner class to scan a network for SNMP devices and send the results to OCS.
    Process is as follows:
        - Retrieve SNMP configuration from the server
        - Scan the network for SNMP devices

    The scanner can operate in two modes:
        - ONLINE: The scanner retrieves the SNMP configuration from the server and sends the results to the server
        - OFFLINE: The scanner uses a local configuration and stores the results locally

    To determine which configuration to use, the scanner checks the server's SNMP configuration and the local configuration.
    If the server's configuration is empty, the scanner uses the local configuration.
    """

    def __init__(self):
        self.read_config()
        self.log_file = DIR + "/logs/snmp_scanner.log"
        logging.basicConfig(
            filename=self.log_file,
            level=self.log_level,
            format="%(asctime)s - %(levelname)s - %(message)s",
        )
        logging.info("Starting SNMP scanner...")
        # endpoints
        self.auth_endpoint = "/api-auth/token"
        self.config_endpoint = "/snmp/config/"
        self.snmp_enabled_endpoint = "/config/snmp/"
        self.asset_endpoint = "/asset/bases/"
        self.template_endpoint = "/templates/"
        self.asset_collection_endpoint = "/asset/collection/"
        self.scanner_endpoint = "/snmp/scanner/"
        self.oids = {
            "description": "1.3.6.1.2.1.1.1.0",
            "name": "1.3.6.1.2.1.1.5.0",
            "srcmac": "1.3.6.1.2.1.2.2.1.6.1",
            "serial": "1.3.6.1.2.1.47.1.1.1.1.11.1",
        }
        self.nb_found = 0
        self.nb_scanned = 0
        self.ip = self.get_scanner_ip()
        self.identifier = self.get_or_create_identifier()

    def get_or_create_identifier(self):
        """Get or create an identifier for the scanner."""
        if self.identifier:
            return self.identifier
        else:
            # if no identifier is found, create one and store it in the configuration file
            identifier = str(uuid.uuid4())
            config = configparser.ConfigParser()
            config.read(DIR + "/config/scanner.conf")
            config.set("scanner", "identifier", identifier)
            with open(DIR + "/config/scanner.conf", "w") as configfile:
                config.write(configfile)
            return identifier

    def get_scanner_ip(self):
        """Get the local IP of the scanner."""
        ip = socket.gethostbyname(socket.gethostname())
        return ip

    def read_config(self):
        """Read the configuration file using configparser."""
        config = configparser.ConfigParser()
        if not os.path.exists(DIR + "/config/scanner.conf"):
            logging.error("Configuration file not found, exiting...")
            exit()
        else:
            config.read(DIR + "/config/scanner.conf")
            self.auth_data = {
                "username": config.get("auth", "ocs_user"),
                "password": config.get("auth", "ocs_password"),
            }
            self.base_url = config.get("api", "ocs_base_url")
            self.mode = config.get("scanner", "scanner_mode")
            self.inventoy_dir = DIR + "/" + config.get("scanner", "local_inventory_dir")
            self.log_level = config.get("scanner", "log_level")
            self.targets = config.get("scanner", "targeted_subnets").split(",")
            self.identifier = config.get("scanner", "identifier")

    def get_auth_token(self, auth_data):
        """
        Get the authentication token from OCS
        """
        url = self.base_url + self.auth_endpoint
        payload = {"username": auth_data["username"], "password": auth_data["password"]}
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, json=payload, headers=headers)

        if response.status_code == 200:
            logging.info("Authentication token retrieved successfully")
            self.token = response.json()["token"]
            return True
        else:
            logging.error(
                f"Failed to retrieve authentication token: {response.status_code}"
            )
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

    def process_snmp_configs(self, configurations):
        """Process the SNMP configurations, matching configurations to the scanner's subnets."""
        # TODO : SNMP configuration format has changed
        # is SNMP enabled on the server?
        check_enabled_url = self.base_url + self.snmp_enabled_endpoint
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {self.token}",
        }
        response = requests.get(check_enabled_url, headers=headers)
        if response.status_code == 200:
            # check if snmp is enabled
            if response.json()["value"][0]["value"] != 1:
                logging.error("SNMP is not enabled on the server, exiting...")
                exit()
            else:
                logging.info("SNMP is enabled on the server")
        else:
            logging.error(
                f"Failed to retrieve SNMP enabled status: {response.status_code}"
            )
            exit()

        processed_configs = []
        # get scanner details
        scanner = self.get_scanner_instance()
        if not scanner:
            logging.info(
                "Scanner instance not found, scan will be performed using the local targeted_subnets configuration. A SnmpScanner instance will be created at the end of the scan."
            )

        # if both scanner['subnets'] and self.targets are defined, server's configuration takes precedence
        if not scanner and self.targets:
            logging.info("Subnets retrieved from local configuration")
        elif scanner and not self.targets:
            self.targets = scanner["subnets"]
            logging.info("Subnets retrieved from the server")
        elif scanner and self.targets:
            self.targets = scanner["subnets"]
            logging.info(
                "Subnets retrieved from the server and local configuration: using server's configuration."
            )
        else:
            logging.error(
                "No subnets defined in local configuration or on the server, exiting..."
            )
            exit()

        # getting configs from the server
        # if we did get the scanner instance, we already have configs
        if scanner and scanner.get("configs"):
            configurations = scanner["configs"]
        else:
            logging.error(
                "No SNMP configurations found for the scanner instance, scan will not be performed."
            )
            # we are not updating last scan date if no scan is performed
            self.scan_date = None
            self.update_or_create_scanner()
            exit()

        for config in configurations:
            # check if the configuration's subnets match the scanner's subnets
            if set(config["subnets"]).intersection(set(scanner.get("subnets"))):
                processed_configs.append(config)

            # TODO : come back here : check what goes into generated_ips_for_configs
            self.generate_ips_for_configs(processed_configs)

        if not processed_configs:
            logging.error(
                "No SNMP configuration matching the scanner's subnets, exiting..."
            )
            exit()

        return processed_configs

    def generate_ips_for_configs(self, parsed_configs):
        """Generate the list of IPs for each configuration."""
        for config in parsed_configs:
            config["ips"] = []
            for subnet in config["subnets"]:
                network = ipaddress.ip_network(subnet)
                config["ips"] += [str(ip) for ip in network.hosts()]

    def get_scanner_instance(self):
        """Get the scanner instance from the server, using scanner's name as unique identifier."""
        url = self.base_url + self.scanner_endpoint + f"{self.identifier}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {self.token}",
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200 and response.json():
            logging.info("Scanner instance retrieved successfully from OCS server")
            return response.json()
        elif response.status_code == 404:
            logging.info(
                f"Scanner instance not found with identifier {self.identifier}"
            )
            return None
        else:
            logging.error(
                f"Failed to retrieve scanner instance: {response.status_code}"
            )
            return None

    def update_or_create_scanner(self):
        """Update or create the scanner instance on the server."""
        url = self.base_url + self.scanner_endpoint + f"{self.identifier}/"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {self.token}",
        }
        total_found = self.nb_found
        total_scanned = self.nb_scanned
        payload = {
            "identifier": self.identifier,
            "ip": self.ip,
            "subnets": self.targets,
            "total_scanned": total_scanned,
            "total_found": total_found,
            "last_scan_date": (
                None
                if not self.scan_date
                else self.scan_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            ),
        }

        response = requests.patch(url, json=payload, headers=headers)
        if response.status_code == 200:
            logging.info("Scanner instance updated successfully")
        elif response.status_code == 404:
            url = self.base_url + self.scanner_endpoint
            # this is post so no issue creating a new scanner instance with empty configs
            payload["configs"] = []
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                logging.info("Scanner instance created successfully")
            else:
                logging.error(
                    f"Failed to create scanner instance: {response.status_code}, reason: {response.json()}"
                )
        else:
            logging.error(
                f"Failed to update scanner instance: {response.status_code}, reason: {response.json()}"
            )

    def retrieve_snmp_configuration(self):
        """Retrieve SNMP configuration from the server."""
        if self.mode == "ONLINE":
            url = self.base_url + self.config_endpoint
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Token {self.token}",
            }
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                self.config = response.json()
                logging.info(
                    "SNMP configuration retrieved successfully from OCS server"
                )
                self.communities = self.process_snmp_configs(self.config)
                logging.info("SNMP configuration parsed successfully")
            else:
                logging.error(
                    f"Failed to retrieve SNMP configuration: {response.status_code}"
                )

        if self.mode == "OFFLINE":
            logging.info("Operating in OFFLINE mode. Using local configuration.")
            if os.path.exists(DIR + "/config/communities.json"):
                with open(DIR + "/config/communities.json", "r") as file:
                    self.communities = json.load(file)
                    self.generate_ips_for_configs(self.communities)
                    logging.info("Local SNMP configuration parsed successfully")
            else:
                logging.error("Local SNMP configuration not found, exiting...")
                exit()

    def parse_subnet_list(self, subnet_str_list):
        """Parse a list of subnet strings into a list of IPNetwork objects."""
        subnets = []
        for subnet in subnet_str_list:
            network = ipaddress.ip_network(subnet)
            subnets.append(network)
        return subnets

    def snmpv1_scan(self, community, ip, oid):
        """Scan the network for SNMPv1 devices."""
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community["name"], mpModel=0),
                UdpTransportTarget(
                    (ip, 161),
                    timeout=community["timeout"],
                    retries=community["retries"],
                ),
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
                CommunityData(community["name"], mpModel=1),
                UdpTransportTarget(
                    (ip, 161),
                    timeout=community["timeout"],
                    retries=community["retries"],
                ),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
        )

        return errorIndication, errorStatus, errorIndex, varBinds

    def snmpv3_scan(self, community, ip, oid):
        """Scan the network for SNMPv3 devices."""
        authProtocol = None
        privProtocol = None
        if community["priv_protocol"] == "DES":
            privProtocol = usmDESPrivProtocol
        elif community["priv_protocol"] == "AES":
            privProtocol = usmAesCfb128Protocol

        if community["auth_protocol"] == "MD5":
            authProtocol = usmHMACMD5AuthProtocol
        elif community["auth_protocol"] == "SHA":
            authProtocol = usmHMACSHAAuthProtocol

        if community["auth_level"] == "authNoPriv":
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(
                    SnmpEngine(),
                    UsmUserData(
                        community["user"],
                        authKey=community["password"],
                        authProtocol=authProtocol,
                    ),
                    UdpTransportTarget(
                        (ip, 161),
                        timeout=community["timeout"],
                        retries=community["retries"],
                    ),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                )
            )
        elif community["auth_level"] == "authPriv":
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(
                    SnmpEngine(),
                    UsmUserData(
                        community["user"],
                        authKey=community["password"],
                        privKey=community["priv_password"],
                        authProtocol=authProtocol,
                        privProtocol=privProtocol,
                    ),
                    UdpTransportTarget(
                        (ip, 161),
                        timeout=community["timeout"],
                        retries=community["retries"],
                    ),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                )
            )
        elif community["auth_level"] == "noAuthNoPriv":
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(
                    SnmpEngine(),
                    UdpTransportTarget(
                        (ip, 161),
                        timeout=community["timeout"],
                        retries=community["retries"],
                    ),
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
            for ip in community["ips"]:
                logging.debug(
                    f"======== Scanning {ip} with community '{community['name']}' ========"
                )
                self.nb_scanned += 1
                device_results = {}
                for name, oid in self.oids.items():
                    found = False
                    logging.debug(f"Getting OID {oid}...")
                    if community["version"] == "2c":
                        errorIndication, errorStatus, errorIndex, varBinds = (
                            self.snmpv2c_scan(community, ip, oid)
                        )
                    elif community["version"] == "1":
                        errorIndication, errorStatus, errorIndex, varBinds = (
                            self.snmpv1_scan(community, ip, oid)
                        )
                    elif community["version"] == "3":
                        errorIndication, errorStatus, errorIndex, varBinds = (
                            self.snmpv3_scan(community, ip, oid)
                        )

                    if errorIndication:
                        logging.debug(f"Error: {errorIndication}")
                    elif errorStatus:
                        logging.debug(f"Error: {errorStatus.prettyPrint()}")
                    else:
                        for varBind in varBinds:
                            logging.debug(f"OID: {oid} - {varBind.prettyPrint()}")
                            device_results[name] = (
                                varBind.prettyPrint().split("=")[1].strip()
                            )
                            found = True
                            results[ip] = device_results
                if found:
                    self.nb_found += 1

        return results

    def advanced_scan(self):
        """Perform advanced scans based on the templates."""
        advanced_results = {}
        template_oids = {}
        logging.info("Starting advanced scan based on templates...")
        # check if the template is indeed an SNMP template and get the OIDs
        for result in self.formatted_results:
            if result["template"] and result["template"]["os"] == "SNMP":
                template_oids[result["srcip"]] = self.decompose_template(
                    result["template"]
                )
            # get rid of the template key (result is what we want to send to the server)
            result.pop("template")

        for community in self.communities:
            for ip in community["ips"]:
                logging.debug(
                    f"======== Advance scanning {ip} with community '{community['name']}' ========"
                )
                device_results = {}
                if ip in template_oids:
                    for section_name, section in template_oids[ip].items():
                        for name, oid in section.items():
                            logging.debug(f"Getting OID {oid}...")
                            if community["version"] == "2c":
                                errorIndication, errorStatus, errorIndex, varBinds = (
                                    self.snmpv2c_scan(community, ip, oid)
                                )
                            elif community["version"] == "1":
                                errorIndication, errorStatus, errorIndex, varBinds = (
                                    self.snmpv1_scan(community, ip, oid)
                                )
                            elif community["version"] == "3":
                                errorIndication, errorStatus, errorIndex, varBinds = (
                                    self.snmpv3_scan(community, ip, oid)
                                )

                            if errorIndication:
                                logging.error(f"Error: {errorIndication}")
                            elif errorStatus:
                                logging.error(f"Error: {errorStatus.prettyPrint()}")
                            else:
                                for varBind in varBinds:
                                    logging.debug(
                                        f"OID: {oid} - {varBind.prettyPrint()}"
                                    )
                                    value = varBind.prettyPrint().split("=")[1].strip()
                                    # if same section name already exists, add the new value to it
                                    if section_name in device_results:
                                        # using the index 0 isnt an issue here bc we know there won't be more than one section
                                        device_results[section_name][0][name] = value
                                    else:
                                        device_results[section_name] = [{name: value}]
                                advanced_results[ip] = device_results

        self.format_to_template(advanced_results)

        return advanced_results

    def decompose_template(self, data):
        # decomposed structure
        decomposed = {}
        for section in data["sections"]:
            section_dict = {}
            for field in section["fields"]:
                # map the field name to its retrieval value
                section_dict[field["name"]] = field["retrival_value"]

            decomposed[section["name"]] = section_dict

        return decomposed

    def send_to_ocs(self):
        """Send formatted data to the server."""
        logging.info("Sending data to OCS...")
        if self.mode == "ONLINE":
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
                    logging.info(
                        f"Device {device['uuid']} created/updated successfully"
                    )
                elif response.status_code not in [200, 201]:
                    logging.error(
                        f"Failed to create/update device {device['uuid']}: {response.status_code}"
                    )

        else:
            logging.info(
                f"Server is not reachable. Storing inventories locally and writing logs to {self.log_file}"
            )
            self.store_data_locally(self.formatted_results)

    def store_data_locally(self, data):
        """Store inventories locally, naming the files with the device's uuid."""
        if os.path.exists(self.inventoy_dir):
            for file in os.listdir(self.inventoy_dir):
                # remove all files in the directory
                os.remove(self.inventoy_dir + "/" + file)

            for device in data:
                filename = "/" + device["uuid"] + ".json"
                with open(self.inventoy_dir + filename, "w") as file:
                    json.dump(device, file)
                    logging.info(f"Device {device['uuid']} stored locally")
        else:
            logging.error(
                f"Local inventory directory {self.inventoy_dir} not found, exiting..."
            )
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
                device_template["uuid"] = (
                    device_template["name"] + "-" + device_template["srcip"]
                )

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
                result["method"] = "PUT"
                # if a template has been assigned
                if existing_asset.get("template"):
                    url = template_url + str(existing_asset["template"])
                    response = requests.get(url, headers=headers)
                    if response.status_code == 200:
                        result["template"] = response.json()
                    else:
                        logging.error(
                            f"Failed to retrieve template: {response.status_code}"
                        )
                        result["template"] = None
                else:
                    logging.info(f"No template assigned to {result['uuid']}")
                    result["template"] = None
            else:
                logging.info(
                    f"Device {result['uuid']} not found, creating new entry..."
                )
                result["template"] = None
                result["method"] = "POST"

    def run(self):
        """Main method to run the scanner."""
        # if the scanner is in ONLINE mode and the server is not reachable, switch to OFFLINE mode
        if self.mode == "ONLINE" and not self.check_server():
            logging.error("Server is not reachable, switching to OFFLINE mode...")
            self.mode = "OFFLINE"
        self.retrieve_snmp_configuration()
        # base scan
        scan_results = self.scan_network()
        self.formatted_results = self.format_to_base(scan_results)

        if self.mode == "ONLINE":
            # associate formatted results with their appropriate templates, based on their uuid
            self.get_templates()
            # perform advanced scans based on templates
            self.advanced_results = self.advanced_scan()
            # sending inventory to OCS
            self.send_to_ocs()
            logging.info(
                f"Scan complete. Found a total of {len(self.formatted_results)} devices"
            )
            # create scanner instance
            self.scan_date = datetime.now()
            self.update_or_create_scanner()

        elif self.mode == "OFFLINE":
            self.store_data_locally(self.formatted_results)
            logging.info(
                f"Inventories stored locally in {self.inventoy_dir}. Scan complete. Found a total of {len(self.formatted_results)} devices."
            )


if __name__ == "__main__":
    scanner = SNMPScanner()
    scanner.run()
