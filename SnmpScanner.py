import asyncio
import configparser
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import uuid
from datetime import datetime

import requests
import urllib3
from pysmi.codegen.pysnmp import baseMibs
from pysmi.reader.localfile import FileReader
from pysmi.reader.url import getReadersFromUrls
from pysmi.searcher.pyfile import PyFileSearcher
from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    EndOfMibView,
    NoSuchInstance,
    NoSuchObject,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    usmAesCfb128Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    walk_cmd,
)
from pysnmp.proto import errind
from pysnmp.smi import compiler, view
from requests.adapters import HTTPAdapter

DIR = os.path.dirname(os.path.abspath(__file__))
VERSION = "3.0.0"
DEFAULT_MAX_CONCURRENT_DEVICES = 50
SCAN_BATCH_SIZE = 1000
# the server stores this for agents without a serial number and ignores it
# when reconciling assets
EMPTY_SERIAL = "Empty"
# walked in this order by get_serial, unless serial_oids is set
DEFAULT_SERIAL_OIDS = {
    "ENTITY-MIB::entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
    "Printer-MIB::prtGeneralSerialNumber": "1.3.6.1.2.1.43.5.1.1.17",
}
NUMERIC_OID_RE = re.compile(r"\.?[0-2](\.\d+)+")
# IF-MIB ifPhysAddress column, walked for srcmac
IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")
# the SNMPv3 protocols the server can configure
AUTH_PROTOCOLS = {"MD5": usmHMACMD5AuthProtocol, "SHA": usmHMACSHAAuthProtocol}
PRIV_PROTOCOLS = {"DES": usmDESPrivProtocol, "AES": usmAesCfb128Protocol}
MIB_MODULE_RE = re.compile(
    rb"^\s*([A-Za-z][\w-]*)\s+DEFINITIONS\b[^:]*::=\s*BEGIN", re.M
)


class SystemStoreAdapter(HTTPAdapter):
    """Verify server certificates against the system trust store.

    This adapter uses the OpenSSL default paths, so the system store is used.
    A cafile is added on top of it rather than replacing it.
    """

    def __init__(self, cafile=None, **kwargs):
        self.cafile = cafile
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context()
        if self.cafile:
            context.load_verify_locations(cafile=self.cafile)
        kwargs["ssl_context"] = context
        return super().init_poolmanager(*args, **kwargs)


class MibDirReader(FileReader):
    """Find the MIBs of mibs_dir by module name, whatever their file name."""

    def __init__(self, mibs_dir, files):
        super().__init__(mibs_dir, recursive=False)
        self.files = files

    def get_mib_variants(self, mibname, **options):
        return [(mibname, self.files[mibname])] if mibname in self.files else []


class SNMPScanner:
    """
    SNMP Scanner class to scan a network for SNMP devices and send the results to OCS.
    Process is as follows:
        - Retrieve SNMP configuration from the server
        - Scan the network for SNMP devices

    The scanner can operate in two modes:
        - ONLINE: The scanner retrieves the SNMP configuration from the
          server and sends the results to the server
        - OFFLINE: The scanner uses a local configuration and stores the results locally

    To determine which configuration to use, the scanner checks the
    server's SNMP configuration and the local configuration.
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
            format=(
                "%(asctime)s - %(levelname)s - "
                "[%(filename)s:%(lineno)d] - %(message)s"
            ),
        )
        logging.info(f"Starting SNMP scanner v{VERSION}...")
        self.certificate_logged = False
        self.log_certificate_mode()
        self.log_scan_concurrency()
        self.session = self.create_session()
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
        }
        self.serial_oids = self.get_serial_oids()
        self.nb_found = 0
        self.nb_scanned = 0
        self.ip = self.get_scanner_ip()
        self.name = self.get_or_create_name()
        # the builder of an engine, so that standard MIBs resolve as in the engines
        self.mib_builder = SnmpEngine().get_mib_builder()
        compiler.add_mib_compiler(self.mib_builder, sources=[self.mibs_dir])
        self.load_mibs(self.mibs_dir)
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

    def load_mibs(self, mibs_dir):
        """
        Compile and load the MIBs of mibs_dir, return the modules loaded.

        Imports are looked up in mibs_dir, then in the system MIB directories.
        A MIB is compiled again only when its file changes.
        """
        files = {}
        for root, _, names in os.walk(mibs_dir):
            for name in names:
                path = os.path.join(root, name)
                try:
                    with open(path, "rb") as f:
                        modules = MIB_MODULE_RE.findall(f.read())
                except OSError as e:
                    logging.error(f"Cannot read MIB file {path}: {e}")
                    continue
                for module in map(bytes.decode, modules):
                    if module in files:
                        logging.warning(
                            f"MIB {module} defined in {files[module]} and {path}, "
                            f"using {path}"
                        )
                    files[module] = path
        if not files:
            logging.info(f"No MIB found in {mibs_dir}")
            return []

        mib_compiler = self.mib_builder.get_mib_compiler()
        mib_compiler.add_sources(
            MibDirReader(mibs_dir, files),
            *getReadersFromUrls(*compiler.DEFAULT_SOURCES),
        )
        mib_compiler.add_searchers(PyFileSearcher(compiler.DEFAULT_DEST))
        # without ignoreErrors, one broken MIB stops the others from compiling
        statuses = mib_compiler.compile(*files, ignoreErrors=True)
        missing = [name for name, status in statuses.items() if status == "missing"]
        if missing:
            logging.error(
                f"MIBs imported but found neither in {mibs_dir} nor in the system "
                f"MIB directories: {', '.join(missing)}"
            )

        ok = ("compiled", "untouched", "borrowed")
        failed = [name for name, status in statuses.items() if status not in ok]
        loaded = []
        for module, path in files.items():
            status = statuses.get(module)
            # SMI definitions, built into pysnmp and pysmi
            if module in baseMibs:
                continue
            if status not in ok:
                error = getattr(status, "error", status)
                logging.error(f"MIB {module} of {path} not compiled: {error}")
                continue
            try:
                self.mib_builder.load_modules(module)
            except Exception as e:
                # pysmi writes a MIB even when one of its imports fails
                imports = [name for name in failed if name in str(e)]
                if imports:
                    reason = f"imports {', '.join(imports)}, not compiled"
                else:
                    reason = str(e).rsplit(" caused by ", 1)[-1]
                logging.error(f"MIB {module} of {path} not loaded: {reason}")
                continue
            loaded.append(module)
        logging.info(
            f"{len(loaded)} MIB modules loaded from {mibs_dir}: {', '.join(loaded)}"
        )
        return loaded

    def get_scanner_ip(self):
        """Get the local IP of the scanner."""
        ip = socket.gethostbyname(socket.gethostname())
        return ip

    def read_config(self):
        """Read the configuration file using configparser."""
        config = configparser.ConfigParser()
        if not os.path.exists(DIR + "/config/scanner.conf"):
            logging.error("Configuration file not found, exiting...")
            exit(1)
        else:
            config.read(DIR + "/config/scanner.conf")
            self.auth_data = {
                "username": config.get("auth", "ocs_user"),
                "password": config.get("auth", "ocs_password"),
            }
            self.base_url = config.get("api", "ocs_base_url")
            self.certificate = config.get("api", "certificate", fallback="").strip()
            self.bypass_certificate = config.getboolean(
                "api", "bypass_certificate", fallback=False
            )
            self.mode = config.get("scanner", "scanner_mode")
            self.inventoy_dir = DIR + "/" + config.get("scanner", "local_inventory_dir")
            self.log_level = config.get("scanner", "log_level")
            self.targets = config.get("scanner", "targeted_subnets").split(",")
            # logging is not set up yet: log_scan_concurrency reports it
            self.max_concurrent_devices = DEFAULT_MAX_CONCURRENT_DEVICES
            self.invalid_max_concurrent_devices = None
            value = config.get("scanner", "max_concurrent_devices", fallback=None)
            if value is not None:
                try:
                    max_concurrent_devices = int(value)
                except ValueError:
                    max_concurrent_devices = 0
                if max_concurrent_devices >= 1:
                    self.max_concurrent_devices = max_concurrent_devices
                else:
                    self.invalid_max_concurrent_devices = value
            self.name = config.get("scanner", "name")
            self.mibs_dir = config.get("scanner", "mibs_dir")
            self.serial_oids_setting = config.get("scanner", "serial_oids", fallback="")
            self.server_logging_enabled = config.getboolean(
                "scanner", "server_logging_enabled", fallback=False
            )
            self.server_log_level = config.get(
                "scanner", "server_log_level", fallback="WARNING"
            ).upper()

    def is_https(self):
        return self.base_url.lower().startswith("https")

    def certificate_file_exists(self):
        return bool(self.certificate) and os.path.isfile(self.certificate)

    def create_session(self, use_certificate_file=False):
        """Build a requests session applying the configured TLS policy."""
        session = requests.Session()
        if not self.is_https():
            return session
        if self.bypass_certificate:
            # would otherwise warn on every single request
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            session.verify = False
            return session
        cafile = None
        if use_certificate_file and self.certificate_file_exists():
            cafile = self.certificate
            if not self.certificate_logged:
                logging.info(f"Using certificate file: {cafile}")
                self.certificate_logged = True
        session.mount("https://", SystemStoreAdapter(cafile))
        return session

    def log_certificate_mode(self):
        """Log which TLS mode is active, once at startup."""
        if not self.is_https():
            logging.info("Certificate mode: TLS disabled (HTTP).")
            return
        if self.bypass_certificate:
            logging.warning(
                "Certificate mode: TLS validation bypassed "
                "(bypass_certificate=true, insecure)."
            )
            return
        if self.certificate_file_exists():
            logging.info(
                "Certificate mode: TLS enabled (system store), fallback "
                f"certificate path available: {self.certificate}"
            )
            return
        if self.certificate:
            logging.warning(
                f"Configured certificate file not found: {self.certificate}"
            )
        logging.info(
            "Certificate mode: TLS enabled (system store), no fallback "
            "certificate path available."
        )

    def log_scan_concurrency(self):
        """Log the scan concurrency, once at startup."""
        if self.invalid_max_concurrent_devices is not None:
            logging.warning(
                "Invalid max_concurrent_devices value "
                f"'{self.invalid_max_concurrent_devices}', expected an integer "
                f">= 1: using the default ({DEFAULT_MAX_CONCURRENT_DEVICES})"
            )
        logging.info(
            f"Scan concurrency: up to {self.max_concurrent_devices} devices at a time"
        )

    def get_serial_oids(self):
        """The OIDs walked by get_serial: serial_oids if set, else the defaults."""
        serial_oids = {}
        for oid in self.serial_oids_setting.split(","):
            oid = oid.strip()
            if NUMERIC_OID_RE.fullmatch(oid):
                serial_oids[oid.lstrip(".")] = oid.lstrip(".")
            elif oid:
                logging.warning(f"serial_oids entry '{oid}' skipped: not a numeric OID")
        if serial_oids:
            return serial_oids
        if self.serial_oids_setting.strip():
            logging.warning("No valid OID in serial_oids, using the default ones")
        return dict(DEFAULT_SERIAL_OIDS)

    def should_try_certificate_fallback(self):
        return (
            self.is_https()
            and not self.bypass_certificate
            and self.certificate_file_exists()
        )

    def request(self, method, url, **kwargs):
        """Send a request, retrying with the certificate file on TLS failure.

        The system trust store is always tried first, so the configured
        certificate extends the trusted roots instead of replacing them.
        """
        try:
            return self.session.request(method, url, **kwargs)
        except requests.exceptions.SSLError as primary_error:
            if not self.should_try_certificate_fallback():
                logging.error(
                    "TLS validation failed using system store. "
                    f"Scanned certificate paths: [{self.certificate}]. "
                    f"Error: {primary_error}"
                )
                raise
            fallback = self.create_session(use_certificate_file=True)
            try:
                response = fallback.request(method, url, **kwargs)
            except requests.exceptions.SSLError as fallback_error:
                logging.error(
                    "TLS validation failed with both system store and "
                    "certificate file. Scanned certificate paths: "
                    f"[{self.certificate}]. Primary error: {primary_error} | "
                    f"Fallback error: {fallback_error}"
                )
                raise
            else:
                self.session.close()
                self.session = fallback
                return response
            finally:
                if self.session is not fallback:
                    fallback.close()

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
            f"server_logger called with asset_id={asset_id}, "
            f"log_level={log_level}, scope={scope}, message={message}"
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
            response = self.request("POST", url, json=payload, headers=headers)
            if response.status_code in [200, 201]:
                logging.info(
                    f"Server log sent for asset {asset_id} "
                    f"(scope: {scope}, level: {log_level})"
                )
            else:
                logging.warning(
                    f"Failed to send server log for asset {asset_id}: "
                    f"{response.status_code}, {response.text}"
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
            response = self.request("POST", url, json=payload, headers=headers)

            if response.status_code == 200:
                self.token = response.json()["token"]
                logging.info("Authentication token retrieved successfully")
                return True
            else:
                logging.error(
                    f"Failed to retrieve authentication token. "
                    f"Status: {response.status_code}, Response: {response.text}"
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
        """
        Process the SNMP configurations, matching configurations to the
        scanner's subnets.
        """
        # is SNMP enabled on the server?
        check_enabled_url = self.base_url + self.snmp_enabled_endpoint
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {self.token}",
        }
        response = self.request("GET", check_enabled_url, headers=headers)
        if response.status_code == 200:
            # check if snmp is enabled
            if response.json()["value"][0]["value"] != 1:
                logging.error("SNMP is not enabled on the server, exiting...")
                exit(1)
            else:
                logging.info("SNMP is enabled on the server")
        else:
            logging.error(
                f"Failed to retrieve SNMP enabled status: {response.status_code}"
            )
            exit(1)

        processed_configs = []
        # get scanner details
        scanner = self.get_scanner_instance()
        if not scanner:
            logging.info(
                "Scanner instance not found, scan will be performed using "
                "the local targeted_subnets configuration. A SnmpScanner "
                "instance will be created at the end of the scan."
            )

        # if both scanner['subnets'] and self.targets are defined,
        # server's configuration takes precedence
        if not scanner and self.targets:
            logging.info("Subnets retrieved from local configuration")
        elif scanner and not self.targets:
            self.targets = scanner["subnets"]
            logging.info("Subnets retrieved from the server")
        elif scanner and self.targets:
            self.targets = scanner["subnets"]
            logging.info(
                "Subnets retrieved from the server and local "
                "configuration: using server's configuration."
            )
        else:
            logging.error(
                "No subnets defined in local configuration or on the server, exiting..."
            )
            exit(1)

        # getting configs from the server
        # if we did get the scanner instance, we already have configs
        if scanner and scanner.get("configs"):
            configurations = scanner["configs"]
        else:
            logging.error(
                "No SNMP configurations found for the scanner instance, "
                "scan will not be performed."
            )
            # we are not updating last scan date if no scan is performed
            self.scan_date = None
            self.update_or_create_scanner()
            exit(1)

        scanner_subnets = self.parse_subnet_list(
            scanner["subnets"], f"scanner {self.name}"
        )
        for config in configurations:
            config_subnets = self.parse_subnet_list(
                config["subnets"], f"SNMP configuration {config.get('id')}"
            )
            # scan the addresses in both subnets: two overlapping CIDR blocks
            # are nested, so their intersection is the smaller one
            matching_subnets = [
                max(config_subnet, scanner_subnet, key=lambda n: n.prefixlen)
                for config_subnet in config_subnets
                for scanner_subnet in scanner_subnets
                if config_subnet.overlaps(scanner_subnet)
            ]
            if matching_subnets:
                config["subnets"] = matching_subnets
                processed_configs.append(config)

        self.generate_ips_for_configs(processed_configs)

        if not processed_configs:
            logging.error(
                "No SNMP configuration matching the scanner's subnets, exiting..."
            )
            exit(1)

        return processed_configs

    def generate_ips_for_configs(self, parsed_configs):
        """Generate the list of IPs for each configuration."""
        for config in parsed_configs:
            config["ips"] = []
            subnets = self.parse_subnet_list(
                config["subnets"], f"SNMP configuration {config.get('id')}"
            )
            for network in subnets:
                config["ips"] += [str(ip) for ip in network.hosts()]
            # the subnets of a configuration may overlap
            config["ips"] = list(dict.fromkeys(config["ips"]))

    def get_scanner_instance(self):
        """Get the scanner instance from the server, using scanner's name."""
        url = self.base_url + self.scanner_endpoint + f"?name={self.name}&expand=*"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Token {self.token}",
        }
        response = self.request("GET", url, headers=headers)
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
            response = self.request("PATCH", url, json=payload, headers=headers)
            if response.status_code == 200:
                logging.info("Scanner instance updated successfully")
            else:
                logging.error(
                    f"Failed to update scanner instance: "
                    f"{response.status_code}, reason: {response.json()}"
                )
        else:
            payload["configs"] = []
            response = self.request("POST", url, json=payload, headers=headers)
            if response.status_code in [200, 201]:
                logging.info("Scanner instance created successfully")
            else:
                logging.error(
                    f"Failed to create scanner instance: "
                    f"{response.status_code}, reason: {response.json()}"
                )

    def retrieve_snmp_configuration(self):
        """Retrieve SNMP configuration from the server."""
        if self.mode == "ONLINE":
            url = self.base_url + self.config_endpoint
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Token {self.token}",
            }
            response = self.request("GET", url, headers=headers)

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
                    exit(1)
            else:
                logging.error("Local SNMP configuration not found, exiting...")
                exit(1)

    def parse_subnet_list(self, subnet_str_list, owner):
        """Parse a list of subnet strings into a list of IPNetwork objects."""
        subnets = []
        for subnet in subnet_str_list:
            try:
                network = ipaddress.ip_network(str(subnet).strip())
            except ValueError as e:
                logging.warning(f"Subnet of {owner} skipped: {e}")
                continue
            subnets.append(network)
        return subnets

    def format_snmp_value(self, oid, value):
        """Convert an SNMP value to the string sent to OCS, None if there is none."""
        # exceptions of RFC 3416, sent instead of a value
        if isinstance(value, (NoSuchObject, NoSuchInstance, EndOfMibView)):
            return None
        data_type = value.__class__.__name__
        if data_type == "OctetString":
            octets = value.asOctets()
            printable = octets.isascii() and octets.decode().isprintable()
            # a MAC address comes as 6 raw bytes, 6 printable characters stay text
            # outside ifPhysAddress
            in_phys_address = str(oid).startswith(IF_PHYS_ADDRESS + ".")
            if len(octets) == 6 and (not printable or in_phys_address):
                return ":".join(f"{b:02x}" for b in octets)
            try:
                return octets.decode("utf-8")
            except UnicodeDecodeError:
                return value.prettyPrint()
        elif data_type == "TimeTicks":
            ticks = int(value)
            days, remain = divmod(ticks / 100, 86400)
            hours, remain = divmod(remain, 3600)
            minutes, seconds = divmod(remain, 60)
            return f"{int(days)}d {int(hours)}h {int(minutes)}m {int(seconds)}s"
        else:
            return value.prettyPrint()

    def set_auth_data(self):
        """Build the authentication data of each configuration, skip invalid ones."""
        configs = []
        for community in self.configs:
            try:
                community["auth_data"] = self.get_auth_data(community)
            except ValueError as e:
                # the name of a v1/v2c configuration is its community
                logging.error(f"SNMP configuration {community.get('id')} skipped: {e}")
                continue
            configs.append(community)
        self.configs = configs

    def get_auth_data(self, community):
        """Return the pysnmp authentication data, ValueError if it is invalid."""
        version = community["version"]
        if version == "1":
            return CommunityData(community["name"], mpModel=0)
        if version == "2c":
            return CommunityData(community["name"], mpModel=1)
        if version != "3":
            raise ValueError(f"unknown SNMP version '{version}'")

        user = community.get("user")
        level = community.get("auth_level")
        if not user:
            raise ValueError("no SNMPv3 user")
        if level == "noAuthNoPriv":
            return UsmUserData(user)
        if level not in ("authNoPriv", "authPriv"):
            raise ValueError(f"unknown SNMPv3 security level '{level}'")

        auth_protocol = AUTH_PROTOCOLS.get(community.get("auth_protocol"))
        password = community.get("password") or ""
        if not auth_protocol:
            raise ValueError(
                f"unknown authentication protocol '{community.get('auth_protocol')}'"
            )
        # RFC 3414, section 11.2
        if len(password) < 8:
            raise ValueError("authentication password shorter than 8 characters")
        if level == "authNoPriv":
            return UsmUserData(user, authKey=password, authProtocol=auth_protocol)

        priv_protocol = PRIV_PROTOCOLS.get(community.get("priv_protocol"))
        priv_password = community.get("priv_password") or ""
        if not priv_protocol:
            raise ValueError(
                f"unknown privacy protocol '{community.get('priv_protocol')}'"
            )
        if len(priv_password) < 8:
            raise ValueError("privacy password shorter than 8 characters")
        return UsmUserData(
            user,
            authKey=password,
            authProtocol=auth_protocol,
            privKey=priv_password,
            privProtocol=priv_protocol,
        )

    async def snmp_scan(
        self, snmp_engine, community, ip, oid, version, mode="SNMP_GET"
    ):
        """Query an OID: a list of (oid, value), None on a timeout or a failure."""
        try:
            transport = await UdpTransportTarget.create(
                (ip, 161), community["timeout"], community["retries"]
            )

            logging.debug(
                f"Initializing SNMP scan for IP: {ip}, OID: {oid}, "
                f"Version: {version}, Mode: {mode}"
            )

            community_data = community["auth_data"]

            results = []
            try:
                if mode == "SNMP_GET":
                    error_indication, error_status, error_index, var_binds = (
                        await get_cmd(
                            snmp_engine,
                            community_data,
                            transport,
                            ContextData(),
                            ObjectType(ObjectIdentity(oid)),
                        )
                    )

                    if error_indication:
                        logging.error(f"SNMP error for IP {ip}: {error_indication}")
                        if isinstance(error_indication, errind.RequestTimedOut):
                            return None
                    elif error_status:
                        logging.error(
                            f"SNMP status error for IP {ip}: "
                            f"{error_status.prettyPrint()}"
                        )
                    else:
                        for var_bind in var_binds:
                            try:
                                oid_str = str(var_bind[0])
                                value_str = self.format_snmp_value(oid_str, var_bind[1])
                                if value_str is None:
                                    logging.debug(
                                        f"No value for IP {ip}: {oid_str} - "
                                        f"{var_bind[1].prettyPrint()}"
                                    )
                                    continue
                                results.append((oid_str, value_str))
                                logging.debug(
                                    f"Successfully processed OID for IP {ip}: "
                                    f"{oid_str} - Value: {value_str}"
                                )

                            except Exception as e:
                                logging.error(
                                    f"Error processing var_bind for IP {ip}: {str(e)}"
                                )
                                continue
                else:  # SNMP_WALK
                    async for (
                        error_indication,
                        error_status,
                        error_index,
                        var_binds,
                    ) in walk_cmd(
                        snmp_engine,
                        community_data,
                        transport,
                        ContextData(),
                        ObjectType(ObjectIdentity(oid)),
                        lexicographicMode=False,
                    ):
                        if error_indication:
                            logging.error(f"SNMP error for IP {ip}: {error_indication}")
                            break
                        elif error_status:
                            logging.error(
                                f"SNMP status error for IP {ip}: "
                                f"{error_status.prettyPrint()}"
                            )
                            break
                        else:
                            for var_bind in var_binds:
                                try:
                                    oid_str = str(var_bind[0])
                                    value_str = self.format_snmp_value(
                                        oid_str, var_bind[1]
                                    )
                                    if value_str is None:
                                        logging.debug(
                                            f"No value for IP {ip}: {oid_str} - "
                                            f"{var_bind[1].prettyPrint()}"
                                        )
                                        continue
                                    results.append((oid_str, value_str))
                                    logging.debug(
                                        f"Successfully processed OID for IP {ip}: "
                                        f"{oid_str} - Value: {value_str}"
                                    )

                                except Exception as e:
                                    logging.error(
                                        f"Error processing var_bind for IP {ip}: "
                                        f"{str(e)}"
                                    )
                                    continue

            except Exception as e:
                logging.error(f"SNMP command execution failed for IP {ip}: {str(e)}")
                return None

            if not results:
                logging.debug(f"No results returned for IP {ip}, OID {oid}")
            else:
                logging.debug(
                    f"Successfully retrieved {len(results)} results "
                    f"for IP {ip}, OID {oid}"
                )

            return results

        except Exception as e:
            logging.error(f"Critical error in SNMP scan for IP {ip}: {str(e)}")
            return None

    def create_snmp_engine(self):
        """Create an SNMP engine for the scan, to close with close_dispatcher()."""
        snmp_engine = SnmpEngine()
        # values resolved with the MIBs loaded at startup, shared by all engines:
        # loading them in each engine takes seconds with hundreds of MIBs
        snmp_engine.cache["mibViewController"] = self.mib_view_controller
        return snmp_engine

    def scan_tasks(self):
        """List the (configuration, IP) pairs to scan, grouped by IP."""
        # each IP keeps the order of the configurations: the last answering wins
        configs_by_ip = {}
        for community in self.configs:
            for ip in community["ips"]:
                configs_by_ip.setdefault(ip, []).append(community)
        return [
            (community, ip)
            for ip, communities in configs_by_ip.items()
            for community in communities
        ]

    def batch_tasks(self, tasks):
        """Split tasks grouped by IP in batches of SCAN_BATCH_SIZE, keeping each IP."""
        batch = []
        for task in tasks:
            if len(batch) >= SCAN_BATCH_SIZE and task[1] != batch[-1][1]:
                yield batch
                batch = []
            batch.append(task)
        if batch:
            yield batch

    async def run_bounded(self, tasks, worker_fn):
        """Run worker_fn on each task concurrently; results keep the task order."""
        results = []
        for batch in self.batch_tasks(tasks):
            # one engine per batch: costly to create, slower with each IP queried;
            # and per configuration: an engine holds a single v3 user per name
            snmp_engines = {}
            try:
                for community, *_ in batch:
                    if id(community) not in snmp_engines:
                        snmp_engines[id(community)] = self.create_snmp_engine()
                results += await self.run_batch(snmp_engines, batch, worker_fn)
            finally:
                for snmp_engine in snmp_engines.values():
                    snmp_engine.close_dispatcher()
        return results

    async def run_batch(self, snmp_engines, tasks, worker_fn):
        results = [None] * len(tasks)
        # shared iterator: each task goes to a single worker
        pending = enumerate(tasks)

        async def worker():
            for index, task in pending:
                snmp_engine = snmp_engines[id(task[0])]
                results[index] = await worker_fn(snmp_engine, *task)

        nb_workers = min(self.max_concurrent_devices, len(tasks))
        workers = [asyncio.create_task(worker()) for _ in range(nb_workers)]
        try:
            await asyncio.gather(*workers)
        finally:
            # gather leaves the other workers running when one fails
            for task in workers:
                task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
        return results

    async def scan_device(self, snmp_engine, community, ip):
        """Scan one IP with one configuration, based on fixed OIDs."""
        logging.debug(
            f"======== Scanning {ip} with community "
            f"'{community['name']}' and version "
            f"'{community['version']}' ========"
        )
        mode = "SNMP_GET"
        device_results = {}
        for name, oid in self.oids.items():
            logging.debug(f"Scanning '{name}' for IP {ip} - OID {oid} with mode {mode}")
            snmp_results = await self.snmp_scan(
                snmp_engine, community, ip, oid, community["version"], mode
            )
            # a silent device: the next OIDs would time out as well
            if snmp_results is None and not device_results:
                break

            if snmp_results:
                for oid, value in snmp_results:
                    device_results[name] = value

            else:
                logging.debug(f"No SNMP response received for IP {ip}, OID {oid}")

        # only devices that answered, a silent IP would time out again
        if device_results:
            device_results["serial"] = await self.get_serial(snmp_engine, community, ip)
            device_results["srcmac"] = await self.get_mac(snmp_engine, community, ip)

        return device_results

    async def get_serial(self, snmp_engine, community, ip):
        """
        Get the serial number of a device, walking the serial_oids columns.

        The first non-empty value wins, whatever its index: the chassis is not
        always entity 1 (e.g. 1001 on a switch stack). Falls back to
        EMPTY_SERIAL, the server rejects an empty serial.
        """
        for mib, column in self.serial_oids.items():
            snmp_results = await self.snmp_scan(
                snmp_engine, community, ip, column, community["version"], "SNMP_WALK"
            )
            for oid, value in snmp_results or []:
                serial = value.replace("\x00", "").strip()
                if serial:
                    logging.debug(f"Serial number of IP {ip} found in {mib}: {oid}")
                    return serial

        logging.warning(
            f"No serial number found for IP {ip} in "
            f"{', '.join(self.serial_oids)}, using '{EMPTY_SERIAL}'"
        )
        return EMPTY_SERIAL

    async def get_mac(self, snmp_engine, community, ip):
        """The MAC address of the first interface that has one, empty if none."""
        snmp_results = await self.snmp_scan(
            snmp_engine,
            community,
            ip,
            IF_PHYS_ADDRESS,
            community["version"],
            "SNMP_WALK",
        )
        for oid, value in snmp_results or []:
            # loopbacks and tunnels have an empty or zero address
            if MAC_RE.fullmatch(value) and value != "00:00:00:00:00:00":
                return value
        return ""

    async def scan_network(self, tasks):
        """Scan the network for SNMP devices, based on fixed OIDs."""
        results = {}
        logging.info("Starting network scan...")
        devices_results = await self.run_bounded(tasks, self.scan_device)
        # as in a one-by-one scan, the last configuration answering wins
        for (community, ip), device_results in zip(tasks, devices_results):
            if device_results:
                results[ip] = device_results

        # an IP covered by several configurations is one device
        self.nb_scanned += len({ip for _, ip in tasks})
        # count the number of devices found
        self.nb_found += len(results)

        return results

    async def advanced_scan_device(self, snmp_engine, community, ip, template):
        """Scan one IP with one configuration, based on its template."""
        logging.debug(
            f"======== Advance scanning {ip} with community "
            f"'{community['name']}' and version "
            f"'{community['version']}' ========"
        )
        device_results = {}
        for section_name, section in template.items():
            logging.debug(f"Processing section {section_name} for IP {ip}...")
            for dic in section:
                name = dic["name"]
                oid = dic["retrieval_value"]
                mode = dic["retrieval_method"]
                logging.debug(
                    f"Scanning '{name}' for IP {ip} - OID {oid} with mode {mode}"
                )
                snmp_results = await self.snmp_scan(
                    snmp_engine, community, ip, oid, community["version"], mode
                )

                if snmp_results:
                    index = 0
                    for oid, value in snmp_results:
                        if section_name in device_results:
                            # use index of the value in snmp_results
                            # to keep track of the order
                            if index < len(device_results[section_name]):
                                device_results[section_name][index][name] = value
                                index += 1
                            else:
                                device_results[section_name].append({name: value})
                                index += 1
                        else:
                            device_results[section_name] = [{name: value}]
                            index += 1
                else:
                    logging.debug(f"No SNMP response received for IP {ip}, OID {oid}")

        return device_results

    async def advanced_scan(self, batch):
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

        tasks = [
            (community, ip, template_oids[ip])
            for community, ip in batch
            if ip in template_oids
        ]
        devices_results = await self.run_bounded(tasks, self.advanced_scan_device)
        for (community, ip, template), device_results in zip(tasks, devices_results):
            if device_results:
                advanced_results[ip] = device_results

        self.format_to_template(advanced_results)
        return advanced_results

    def decompose_template(self, data):
        # decomposed structure
        decomposed = {}
        for section in data["sections"]:
            # the server refuses data for an inactive section
            if not section.get("is_active", True):
                logging.debug(f"Skipping inactive section {section['name']}")
                continue
            section_dict = []
            for field in section["fields"]:
                if not field["retrieval_value"]:
                    continue
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
                        f"Processing device {device.get('uuid', 'unknown')} "
                        f"with method {method}"
                    )

                    if method == "PUT":
                        response = self.request(
                            "PUT", url, json=device, headers=headers
                        )
                    elif method == "POST":
                        response = self.request(
                            "POST", url, json=device, headers=headers
                        )
                    else:
                        logging.error(
                            f"Invalid method {method} for device "
                            f"{device.get('uuid', 'unknown')}"
                        )
                        continue

                    if response.status_code in [200, 201]:
                        msg = (
                            f"Device {device['uuid']} successfully "
                            f"{'created' if method == 'POST' else 'updated'}"
                        )
                        logging.info(msg)
                        # keeping ids of created/updated assets to update
                        # scanner instance
                        asset_id = response.json()["id"]
                        assets.append(asset_id)
                        # server logging
                        scope = (
                            "INVENTORY_BASE_INSERT"
                            if method == "POST"
                            else "INVENTORY_BASE_UPDATE"
                        )
                        self.server_logger(asset_id, "INFO", scope, msg)
                        if device["serial"] == EMPTY_SERIAL:
                            self.server_logger(
                                asset_id,
                                "WARNING",
                                scope,
                                "No serial number found on the device, "
                                f"stored as '{EMPTY_SERIAL}'",
                            )
                    else:
                        logging.error(
                            f"Failed to {'create' if method == 'POST' else 'update'} "
                            f"device {device['uuid']}. "
                            f"Status: {response.status_code}, Response: {response.text}"
                        )

                        self.server_logger(
                            asset_id,
                            "ERROR",
                            "INVENTORY_BASE_ERR",
                            f"Failed to {'create' if method == 'POST' else 'update'} "
                            f"SNMP asset",
                        )

                except requests.exceptions.RequestException as e:
                    logging.error(
                        f"Network error while processing device "
                        f"{device.get('uuid', 'unknown')}: {str(e)}"
                    )
                except Exception as e:
                    logging.error(
                        f"Unexpected error while processing device "
                        f"{device.get('uuid', 'unknown')}: {str(e)}"
                    )

        else:
            logging.info(
                f"Operating in OFFLINE mode. "
                f"Storing data locally in {self.inventoy_dir}"
            )
            try:
                self.store_data_locally(self.formatted_results)
            except Exception as e:
                logging.error(f"Failed to store data locally: {str(e)}")

        return assets

    def clear_local_inventories(self):
        """Empty the local inventory directory before the scan."""
        if os.path.exists(self.inventoy_dir):
            for file in os.listdir(self.inventoy_dir):
                os.remove(self.inventoy_dir + "/" + file)
        else:
            logging.error(
                f"Local inventory directory {self.inventoy_dir} not found, exiting..."
            )
            exit(1)

    def store_data_locally(self, data):
        """Store inventories locally, naming the files with the device's uuid."""
        for device in data:
            filename = "/" + device["uuid"] + ".json"
            with open(self.inventoy_dir + filename, "w") as file:
                json.dump(device, file)
                logging.info(f"Device {device['uuid']} stored locally")

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

            # the server refuses an asset without a name
            if not device_template["name"].strip():
                logging.warning(f"No sysName for IP {ip}, using the IP as name")
                device_template["name"] = ip

            if not device_template["uuid"]:
                device_template["uuid"] = (
                    device_template["name"] + "-" + device_template["srcip"]
                )

            formatted_results.append(device_template)

        return formatted_results

    def format_to_template(self, advanced_results):
        """
        Merge the advanced results with the formatted results for template
        inventory.
        """
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
            response = self.request("GET", url, headers=headers)
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
        if self.mode == "ONLINE" and not self.check_server():
            logging.error("Cannot authenticate on the OCS server, exiting...")
            exit(1)
        self.retrieve_snmp_configuration()
        if not self.configs:
            logging.error(
                "No SNMP configuration loaded : Failed to retrieve SNMP "
                "configuration (403). Check OCS user permissions."
            )
            exit(1)
        self.set_auth_data()
        if self.mode == "OFFLINE":
            self.clear_local_inventories()

        # each batch is sent before the next one is scanned: a stop loses one batch
        batches = list(self.batch_tasks(self.scan_tasks()))
        for number, batch in enumerate(batches, 1):
            logging.info(f"Scanning batch {number}/{len(batches)}")
            # base scan
            scan_results = await self.scan_network(batch)
            self.formatted_results = self.format_to_base(scan_results)

            if self.mode == "ONLINE":
                # associate formatted results with their appropriate templates,
                # based on their uuid
                self.get_templates()
                # perform advanced scans based on templates
                self.advanced_results = await self.advanced_scan(batch)
                # sending inventory to OCS
                self.assets += self.send_to_ocs()

            elif self.mode == "OFFLINE":
                self.store_data_locally(self.formatted_results)

        if self.mode == "ONLINE":
            logging.info(f"Scan complete. Found a total of {self.nb_found} devices")
            # create scanner instance
            self.scan_date = datetime.now()
            self.update_or_create_scanner()

        elif self.mode == "OFFLINE":
            logging.info(
                f"Inventories stored locally in {self.inventoy_dir}. "
                f"Scan complete. Found a total of {self.nb_found} devices."
            )


if __name__ == "__main__":
    asyncio.run(SNMPScanner().run())
