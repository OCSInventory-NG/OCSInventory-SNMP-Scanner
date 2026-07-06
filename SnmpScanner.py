import asyncio
import configparser
import ipaddress
import json
import logging
import os
import socket
import uuid
from datetime import datetime

import requests
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    get_cmd,
    next_cmd,
    usmAesCfb128Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
)
from pysnmp.smi import builder, compiler, view

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
        self.configs = None
        self.read_config()
        self.log_file = DIR + "/logs/snmp_scanner.log"
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        logging.basicConfig(
            filename=self.log_file,
            level=self.log_level,
            format="%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s",
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
        self.name = self.get_or_create_name()
        self.mib_builder = builder.MibBuilder()
        compiler.add_mib_compiler(self.mib_builder, sources=[self.mibs_dir])
        self.load_mib_dir(self.mibs_dir)
        self.mib_view_controller = view.MibViewController(self.mib_builder)
        self.assets = []
        self.log_levels = {
            "CRITICAL": 0,
            "ERROR": 1,
            "WARNING": 2,
            "INFO": 3,
            "DEBUG": 4,
        }

    def get_or_create_name(self):
        """Get or create a name for the scanner."""
        if self.name:
            return self.name
        else:
            # if no name is found, create one and store it in the configuration file
            name = str(uuid.uuid4())
            config = configparser.ConfigParser()
            config.read(DIR + "/config/scanner.conf")
            config.set("scanner", "name", name)
            with open(DIR + "/config/scanner.conf", "w") as configfile:
                config.write(configfile)
            return name

    def load_mib_dir(self, mib_path):
        """Load all MIB files in a directory."""
        for root, dirs, files in os.walk(mib_path):
            for file in files:
                logging.debug(f"Loading MIB file: {file}")
                mib_file = os.path.join(root, file)
                self.load_mib_file(mib_file)

            for dire in dirs:
                logging.debug(f"Loading MIB directory: {dire}")
                self.load_mib_dir(os.path.join(root, dire))

    def load_mib_file(self, mib_file):
        """Load a MIB file."""
        mib_name = os.path.splitext(os.path.basename(mib_file))[0]
        try:
            self.mib_builder.loadModules(mib_name)
        except Exception as e:
            logging.error(f"Error loading MIB {mib_name} from file {mib_file}: {e}")

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
            self.name = config.get("scanner", "name")
            self.mibs_dir = config.get("scanner", "mibs_dir")
            self.server_logging_enabled = config.getboolean(
                "scanner", "server_logging_enabled", fallback=False
            )
            self.server_log_level = config.get(
                "scanner", "server_log_level", fallback="WARNING"
            ).upper()

    def server_logger(self, asset_id, log_level, scope, message):
        """
        Optionally send a log to the OCS server for a given asset and event.
        Only sends if server_logging_enabled and in ONLINE mode.
        """
        if asset_id is None:
            logging.warning(
                "server_logger called with asset_id=None, skipping log send."
            )
            return
        logging.debug(
            f"server_logger called with asset_id={asset_id}, log_level={log_level}, scope={scope}, message={message}"
        )
        if not getattr(self, "server_logging_enabled", False):
            logging.debug("Server logging is disabled by config.")
            return
        if getattr(self, "mode", "OFFLINE") != "ONLINE":
            logging.debug("Server logging skipped: not in ONLINE mode.")
            return
        # check level
        if self.log_levels[log_level] > self.log_levels.get(self.server_log_level, 2):
            return
        url = self.base_url + "/asset/logs/"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {self.token}",
        }
        payload = {
            "asset": asset_id,
            "scope": scope,
            "comment": message,
            "level": log_level,
        }
        try:
            logging.debug(f"Sending server log: {payload}")
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code in [200, 201]:
                logging.info(
                    f"Server log sent for asset {asset_id} (scope: {scope}, level: {log_level})"
                )
            else:
                logging.warning(
                    f"Failed to send server log for asset {asset_id}: {response.status_code}, {response.text}"
                )
        except Exception as e:
            logging.error(
                f"Exception while sending server log for asset {asset_id}: {e}"
            )

    def get_auth_token(self, auth_data):
        """Get the authentication token from OCS"""
        try:
            url = self.base_url + self.auth_endpoint
            payload = {
                "username": auth_data["username"],
                "password": auth_data["password"],
            }
            headers = {"Content-Type": "application/json"}

            logging.debug(
                f"Attempting authentication with username: {auth_data['username']}"
            )
            response = requests.post(url, json=payload, headers=headers)

            if response.status_code == 200:
                self.token = response.json()["token"]
                logging.info("Authentication token retrieved successfully")
                return True
            else:
                logging.error(
                    f"Failed to retrieve authentication token. Status: {response.status_code}, Response: {response.text}"
                )
                return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Network error during authentication: {str(e)}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error during authentication: {str(e)}")
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
            scanner_subnets = set(scanner.get("subnets"))
            config_subnets = set(config["subnets"])
            # check if the configuration's subnets match the scanner's subnets
            matching_subnets = scanner_subnets.intersection(config_subnets)
            if matching_subnets:
                config["subnets"] = matching_subnets
                processed_configs.append(config)

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
        """Get the scanner instance from the server, using scanner's name."""
        url = self.base_url + self.scanner_endpoint + f"?name={self.name}&expand=*"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {self.token}",
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200 and response.json():
            logging.info("Scanner instance retrieved successfully from OCS server")
            return response.json()[0]
        elif response.status_code == 404:
            logging.info(f"Scanner instance not found with name {self.name}")
            return None
        else:
            logging.error(
                f"Failed to retrieve scanner instance: {response.status_code}"
            )
            return None

    def update_or_create_scanner(self):
        """Update or create the scanner instance on the server."""
        scanner = self.get_scanner_instance()
        url = (
            self.base_url + self.scanner_endpoint + f"{scanner['id']}/"
            if scanner
            else self.base_url + self.scanner_endpoint
        )
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {self.token}",
        }
        total_found = self.nb_found
        total_scanned = self.nb_scanned
        payload = {
            "name": self.name,
            "ip": self.ip,
            "subnets": self.targets,
            "total_scanned": total_scanned,
            "total_found": total_found,
            "last_scan_date": (
                None
                if not self.scan_date
                else self.scan_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            ),
            "assets": self.assets,
        }

        if scanner:
            response = requests.patch(url, json=payload, headers=headers)
            if response.status_code == 200:
                logging.info("Scanner instance updated successfully")
            else:
                logging.error(
                    f"Failed to update scanner instance: {response.status_code}, reason: {response.json()}"
                )
        else:
            payload["configs"] = []
            response = requests.post(url, json=payload, headers=headers)
            if response.status_code in [200, 201]:
                logging.info("Scanner instance created successfully")
            else:
                logging.error(
                    f"Failed to create scanner instance: {response.status_code}, reason: {response.json()}"
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
                self.configs = self.process_snmp_configs(self.config)
                logging.info("SNMP configuration parsed successfully")
            else:
                logging.error(
                    f"Failed to retrieve SNMP configuration: {response.status_code}"
                )
                self.configs = None

        if self.mode == "OFFLINE":
            logging.info("Operating in OFFLINE mode. Using local configuration.")
            if os.path.exists(DIR + "/config/configs.json"):
                try:
                    with open(DIR + "/config/configs.json", "r") as file:
                        self.configs = json.load(file)
                        self.generate_ips_for_configs(self.configs)
                        logging.info("Local SNMP configuration parsed successfully")
                except Exception as e:
                    logging.error(f"Failed to parse local configuration: {e}")
                    exit()
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

    async def snmp_scan(self, community, ip, oid, version, mode="SNMP_GET"):
        """Scan the network for SNMP devices."""
        try:
            transport = await UdpTransportTarget.create(
                (ip, 161), community["timeout"], community["retries"]
            )

            logging.debug(
                f"Initializing SNMP scan for IP: {ip}, OID: {oid}, Version: {version}, Mode: {mode}"
            )

            if version == "1":
                community_data = CommunityData(community["name"], mpModel=0)
            elif version == "2c":
                community_data = CommunityData(community["name"], mpModel=1)
            elif version == "3":
                # validate SNMP v3 user parameters
                user = community.get("user", "")
                password = community.get("password", "")
                priv_password = community.get("priv_password", "")

                auth_protocol = (
                    usmHMACMD5AuthProtocol
                    if community["auth_protocol"] == "MD5"
                    else usmHMACSHAAuthProtocol
                )
                priv_protocol = (
                    usmDESPrivProtocol
                    if community["priv_protocol"] == "DES"
                    else usmAesCfb128Protocol
                )

                if community["auth_level"] == "authNoPriv":
                    community_data = CommunityData(
                        user, authKey=password, authProtocol=auth_protocol
                    )
                elif community["auth_level"] == "authPriv":
                    community_data = CommunityData(
                        user,
                        authKey=password,
                        authProtocol=auth_protocol,
                        privKey=priv_password,
                        privProtocol=priv_protocol,
                    )
                else:
                    community_data = CommunityData(user)

            results = []
            try:
                if mode == "SNMP_GET":
                    error_indication, error_status, error_index, var_binds = (
                        await get_cmd(
                            SnmpEngine(),
                            community_data,
                            transport,
                            ContextData(),
                            ObjectType(ObjectIdentity(oid)),
                        )
                    )

                    if error_indication:
                        logging.error(f"SNMP error: {error_indication}")
                    elif error_status:
                        logging.error(
                            f"SNMP status error: {error_status.prettyPrint()}"
                        )
                    else:
                        for var_bind in var_binds:
                            try:
                                data_type = var_bind[1].__class__.__name__
                                oid_str = str(var_bind[0])
                                value_str = None
                                if data_type == "OctetString":
                                    # mac address ?
                                    if len(var_bind[1].asOctets()) == 6:
                                        value_str = ":".join(
                                            f"{b:02x}" for b in var_bind[1].asOctets()
                                        )
                                    else:
                                        try:
                                            value_str = (
                                                var_bind[1].asOctets().decode("utf-8")
                                            )
                                        except UnicodeDecodeError:
                                            value_str = var_bind[1].prettyPrint()
                                # timeticks data type
                                elif data_type == "TimeTicks":
                                    ticks = int(var_bind[1])
                                    days, remain = divmod(ticks / 100, 86400)
                                    hours, remain = divmod(remain, 3600)
                                    minutes, seconds = divmod(remain, 60)
                                    value_str = f"{int(days)}d {int(hours)}h {int(minutes)}m {int(seconds)}s"
                                else:
                                    value_str = var_bind[1].prettyPrint()

                                results.append((oid_str, value_str))
                                logging.debug(
                                    f"Successfully processed OID: {oid_str} - Value: {value_str}"
                                )

                            except Exception as e:
                                logging.error(
                                    f"Error processing var_bind for IP {ip}: {str(e)}"
                                )
                                continue
                else:  # SNMP_WALK

                    next = next_cmd(
                        SnmpEngine(),
                        community_data,
                        transport,
                        ContextData(),
                        ObjectType(ObjectIdentity(oid)),
                        lexicographicMode=False,
                    )

                    for (
                        error_indication,
                        error_status,
                        error_index,
                        var_binds,
                    ) in await next:
                        if error_indication:
                            logging.error(f"SNMP error: {error_indication}")
                            break
                        elif error_status:
                            logging.error(
                                f"SNMP status error: {error_status.prettyPrint()}"
                            )
                            break
                        else:
                            for var_bind in var_binds:
                                try:
                                    data_type = var_bind[1].__class__.__name__
                                    oid_str = str(var_bind[0])
                                    value_str = None
                                    if data_type == "OctetString":
                                        # mac address ?
                                        if len(var_bind[1].asOctets()) == 6:
                                            value_str = ":".join(
                                                f"{b:02x}"
                                                for b in var_bind[1].asOctets()
                                            )
                                        else:
                                            try:
                                                value_str = (
                                                    var_bind[1]
                                                    .asOctets()
                                                    .decode("utf-8")
                                                )
                                            except UnicodeDecodeError:
                                                value_str = var_bind[1].prettyPrint()
                                    # timeticks data type
                                    elif data_type == "TimeTicks":
                                        ticks = int(var_bind[1])
                                        days, remain = divmod(ticks / 100, 86400)
                                        hours, remain = divmod(remain, 3600)
                                        minutes, seconds = divmod(remain, 60)
                                        value_str = f"{int(days)}d {int(hours)}h {int(minutes)}m {int(seconds)}s"
                                    else:
                                        value_str = var_bind[1].prettyPrint()

                                    results.append((oid_str, value_str))
                                    logging.debug(
                                        f"Successfully processed OID: {oid_str} - Value: {value_str}"
                                    )

                                except Exception as e:
                                    logging.error(
                                        f"Error processing var_bind for IP {ip}: {str(e)}"
                                    )
                                    continue

            except Exception as e:
                logging.error(f"SNMP command execution failed for IP {ip}: {str(e)}")
                return None

            if not results:
                logging.debug(f"No results returned for IP {ip}, OID {oid}")
            else:
                logging.debug(
                    f"Successfully retrieved {len(results)} results for IP {ip}, OID {oid}"
                )

            return results

        except Exception as e:
            logging.error(f"Critical error in SNMP scan for IP {ip}: {str(e)}")
            return None

    async def scan_network(self):
        """Scan the network for SNMP devices, based on fixed OIDs."""
        results = {}
        logging.info("Starting network scan...")
        mode = "SNMP_GET"
        for community in self.configs:
            for ip in community["ips"]:
                logging.debug(
                    f"======== Scanning {ip} with community '{community['name']}' and version '{community['version']}' ========"
                )
                self.nb_scanned += 1
                device_results = {}
                for name, oid in self.oids.items():
                    logging.debug(f"Scanning '{name}' - OID {oid} with mode {mode}")
                    snmp_results = await self.snmp_scan(
                        community, ip, oid, community["version"], mode
                    )

                    if snmp_results:
                        for oid, value in snmp_results:
                            device_results[name] = value
                        results[ip] = device_results

                    else:
                        logging.debug("No SNMP response received")

        # count the number of devices found
        self.nb_found = len(results)

        return results

    async def advanced_scan(self):
        """Perform advanced scans based on the templates."""
        advanced_results = {}
        template_oids = {}
        logging.info("Starting advanced scan based on templates...")
        for result in self.formatted_results:
            if result["template"] and result["template"]["os"] == "SNMP":
                template_oids[result["srcip"]] = self.decompose_template(
                    result["template"]
                )
            result.pop("template")

        for community in self.configs:
            for ip in community["ips"]:
                logging.debug(
                    f"======== Advance scanning {ip} with community '{community['name']}' and version '{community['version']}' ========"
                )
                device_results = {}
                if ip in template_oids:
                    for section_name, section in template_oids[ip].items():
                        logging.debug(f"Processing section {section_name}...")
                        for dic in section:
                            name = dic["name"]
                            oid = dic["retrieval_value"]
                            mode = dic["retrieval_method"]
                            logging.debug(
                                f"Scanning '{name}' - OID {oid} with mode {mode}"
                            )
                            snmp_results = await self.snmp_scan(
                                community, ip, oid, community["version"], mode
                            )

                            if snmp_results:
                                index = 0
                                for oid, value in snmp_results:
                                    if section_name in device_results:
                                        # use index of the value in snmp_results to keep track of the order
                                        if index < len(device_results[section_name]):
                                            device_results[section_name][index][
                                                name
                                            ] = value
                                            index += 1
                                        else:
                                            device_results[section_name].append(
                                                {name: value}
                                            )
                                            index += 1
                                    else:
                                        device_results[section_name] = [{name: value}]
                                        index += 1
                                advanced_results[ip] = device_results
                            else:
                                logging.debug("No SNMP response received")

        self.format_to_template(advanced_results)
        return advanced_results

    def decompose_template(self, data):
        # decomposed structure
        decomposed = {}
        for section in data["sections"]:
            section_dict = []
            for field in section["fields"]:
                field_dict = {}
                # map the field name to its retrieval value
                field_dict["name"] = field["name"]
                field_dict["retrieval_value"] = field["retrieval_value"]
                field_dict["retrieval_method"] = section["retrieval_method"]
                section_dict.append(field_dict)

            decomposed[section["name"]] = section_dict

        return decomposed

    def send_to_ocs(self):
        """Send data to OCS server"""
        logging.info("Starting data transmission to OCS...")
        assets = []

        if self.mode == "ONLINE":
            url = self.base_url + self.asset_collection_endpoint
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Token {self.token}",
            }

            for device in self.formatted_results:
                try:
                    method = device.pop("method")
                    logging.debug(
                        f"Processing device {device.get('uuid', 'unknown')} with method {method}"
                    )

                    if method == "PUT":
                        response = requests.put(url, json=device, headers=headers)
                    elif method == "POST":
                        response = requests.post(url, json=device, headers=headers)
                    else:
                        logging.error(
                            f"Invalid method {method} for device {device.get('uuid', 'unknown')}"
                        )
                        continue

                    if response.status_code in [200, 201]:
                        msg = f"Device {device['uuid']} successfully {'created' if method == 'POST' else 'updated'}"
                        logging.info(msg)
                        # keeping ids of created/updated assets to update scanner instance
                        asset_id = response.json()["id"]
                        assets.append(asset_id)
                        # server logging
                        self.server_logger(
                            asset_id,
                            "INFO",
                            f"{'INVENTORY_BASE_INSERT' if method == 'POST' else 'INVENTORY_BASE_UPDATE'}",
                            msg,
                        )
                    else:
                        logging.error(
                            f"Failed to {'create' if method == 'POST' else 'update'} device {device['uuid']}. "
                            f"Status: {response.status_code}, Response: {response.text}"
                        )

                        self.server_logger(
                            asset_id,
                            "ERROR",
                            "INVENTORY_BASE_ERR",
                            f"Failed to {'create' if method == 'POST' else 'update'} SNMP asset",
                        )

                except requests.exceptions.RequestException as e:
                    logging.error(
                        f"Network error while processing device {device.get('uuid', 'unknown')}: {str(e)}"
                    )
                except Exception as e:
                    logging.error(
                        f"Unexpected error while processing device {device.get('uuid', 'unknown')}: {str(e)}"
                    )

        else:
            logging.info(
                f"Operating in OFFLINE mode. Storing data locally in {self.inventoy_dir}"
            )
            try:
                self.store_data_locally(self.formatted_results)
            except Exception as e:
                logging.error(f"Failed to store data locally: {str(e)}")

        return assets

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

        base_template = {
            "name": "",
            "description": "",
            "serial": "",
            "osname": "SNMP",
            "osversion": "",
            "uuid": "",
            "srcip": "",
            "srcmac": "",
            "domain": "",
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
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Token " + self.token,
        }

        for result in self.formatted_results:
            # check if the device exists already
            url = asset_url + result["uuid"] + "&expand=*"
            response = requests.get(url, headers=headers)
            if response.status_code == 200 and response.json():
                existing_asset = response.json()[0]
                asset_id = response.json()[0]["id"]
                result["method"] = "PUT"
                # if a template has been assigned
                if existing_asset.get("template"):
                    result["template"] = existing_asset["template"]
                else:
                    logging.info(f"No template assigned to {result['uuid']}")
                    self.server_logger(
                        asset_id,
                        "DEBUG",
                        "INVENTORY_EXT_ERR",
                        "No template assigned to SNMP asset",
                    )
                    result["template"] = None
            else:
                logging.info(
                    f"Device {result['uuid']} not found, creating new entry..."
                )
                result["template"] = None
                result["method"] = "POST"

    async def run(self):
        """Main method to run the scanner."""
        # if the scanner is in ONLINE mode and the server is not reachable, switch to OFFLINE mode
        if self.mode == "ONLINE" and not self.check_server():
            logging.error("Server is not reachable, switching to OFFLINE mode...")
            self.mode = "OFFLINE"
        self.retrieve_snmp_configuration()
        if not self.configs:
            logging.error(
                "No SNMP configuration loaded : Failed to retrieve SNMP configuration (403). Check OCS user permissions."
            )
            exit()

        # base scan
        scan_results = await self.scan_network()
        self.formatted_results = self.format_to_base(scan_results)

        if self.mode == "ONLINE":
            # associate formatted results with their appropriate templates, based on their uuid
            self.get_templates()
            # perform advanced scans based on templates
            self.advanced_results = await self.advanced_scan()
            # sending inventory to OCS
            self.assets = self.send_to_ocs()
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
    asyncio.run(SNMPScanner().run())
