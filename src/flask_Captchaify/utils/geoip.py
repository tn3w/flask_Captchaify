import os
import time
import socket
import urllib.error
import urllib.request
from typing import Final, Optional, Dict

import geoip2.database
from geoip2.errors import AddressNotFoundError, GeoIP2Error

try:
    from src.BotBlocker.utils.utilities import cache_with_ttl
    from src.BotBlocker.utils.files import DATA_DIRECTORY_PATH
except ImportError:
    try:
        from utils.utilities import cache_with_ttl
        from utils.files import DATA_DIRECTORY_PATH
    except ImportError:
        from utilities import cache_with_ttl
        from files import DATA_DIRECTORY_PATH


GEOIP_DATABASES: Final[Dict[str, str]] = {
    "city": "https://git.io/GeoLite2-City.mmdb",
    "asn": "https://git.io/GeoLite2-ASN.mmdb",
    "anonymous": None
}
REQUEST_HEADERS: Final[Dict[str, str]] = {"User-Agent": "Mozilla/5.0"}


def find_geoip_database_path(database_name: str) -> Optional[str]:
    """
    Searches for the path of a GeoIP database file in the specified data directory.

    Args:
        database_name (str): The name of the GeoIP database to search for.

    Returns:
        Optional[str]: The full path to the GeoIP database file if found and valid, 
                       or None if no valid file is found.
    """

    for file in os.listdir(DATA_DIRECTORY_PATH):
        name_portion = "geoip_" + database_name
        if not file.startswith(name_portion):
            continue

        timestamp = file.replace(name_portion, "").split(".")[0]
        if not timestamp.isdigit():
            continue

        full_path = os.path.join(DATA_DIRECTORY_PATH, file)

        if int(time.time()) - int(timestamp) > 604800:
            os.remove(full_path)
            continue

        return full_path

    return None


def download_file(url: str, file_path: str, timeout: int = 3) -> bool:
    """
    Downloads a file from the specified URL and saves it to the given file path.

    Args:
        url (str): The URL to send the GET request to.
        file_path (str): The file path where the downloaded file will be saved.
        timeout (int): The duration after which the connection is cancelled.
    
    Returns:
        bool (bool): True if the file was downloaded and saved successfully, False otherwise.
    """

    req = urllib.request.Request(url, headers = REQUEST_HEADERS)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            with open(file_path, "wb") as file:
                file.write(response.read())

        return True
    except (urllib.error.HTTPError, urllib.error.URLError,
            socket.timeout, FileNotFoundError, PermissionError):
        pass

    return False


@cache_with_ttl(28800)
def download_geoip_databases() -> dict:
    """
    Downloads GeoIP databases and returns their file paths.

    Returns:
        dict: A dictionary where the keys are the names of the GeoIP databases and the values
              are the corresponding file paths. If a database could not be found or downloaded,
              it will not be included in the dictionary.
    """

    geoip_file_paths = {}
    for database_name, database_download_url in GEOIP_DATABASES.items():
        if database_download_url is None:
            continue

        manual_database_path = os.path.join(
            DATA_DIRECTORY_PATH, "mgeoip_" + database_name + ".mmdb"
        )

        if os.path.isfile(manual_database_path):
            geoip_file_paths[manual_database_path] = manual_database_path

        database_path = find_geoip_database_path(database_name)
        if database_path is not None:
            geoip_file_paths[database_name] = database_path
            continue

        new_file_name = "geoip_" + database_name + str(int(time.time())) + ".mmdb"
        new_file_path = os.path.join(DATA_DIRECTORY_PATH, new_file_name)

        successfully_downloaded = download_file(database_download_url, new_file_path)
        if successfully_downloaded:
            geoip_file_paths[database_name] = new_file_path

    return geoip_file_paths


class GeoIP:
    """
    An interface for GeoIP services.

    This class serves as a base class for GeoIP implementations, providing
    a common interface for retrieving geographical information based on IP addresses.

    Attributes:
        geoip_file_path (Optional[str]): The file path to the GeoIP database.
        reader (geoip2.database.Reader): An instance of the GeoIP database reader.
    """


    def __init__(self, geoip_file_path: Optional[str]) -> None:
        """
        Initializes the GeoIP instance with the specified database file path.

        Args:
            geoip_file_path (Optional[str]): The file path to the GeoIP database.
        """

        self.geoip_file_path = geoip_file_path

        if geoip_file_path is None or not os.path.isfile(geoip_file_path):
            self.reader = None
            return

        try:
            self.reader = geoip2.database.Reader(geoip_file_path)
        except (FileNotFoundError, PermissionError, GeoIP2Error):
            self.reader = None


    @property
    def fields(self) -> list:
        """
        Retrieves a list of field names related to geographical and location-based data.

        Returns:
            list: A list of strings representing the field names.
        """


    @property
    def is_available(self) -> bool:
        """
        Checks the availability of the GeoIP database reader.

        Returns:
            bool: True if the GeoIP database reader is available, False otherwise.
        """

        return self.reader is not None


    def get(self, ip_address: str) -> Optional[dict]:
        """
        Retrieves information for the given IP address.

        Args:
            ip_address (str): The IP address to look up.

        Returns:
            Optional[dict]: A dictionary containing information,
                or None if the information cannot be retrieved.
        """

        return None or ip_address


class CityGeoIP(GeoIP):
    """
    A GeoIP implementation that retrieves city-level geographical information.

    This class extends the GeoIP interface to provide detailed city-level
    information based on IP addresses.

    Methods:
        get(ip_address: str) -> dict: Retrieves city-level geographical
        information for the specified IP address.
    """


    @property
    def fields(self) -> list:
        return [
            "city_name", "city_names", "city_locales", "city_confidence",
            "city_geoname_id", "postal_code", "postal_confidence", "country_name",
            "country_names", "country_locales", "country_is_in_eu", "country_confidence",
            "country_iso_code", "country_geoname_id", "registered_country_name",
            "registered_country_names", "registered_country_locales",
            "registered_country_is_in_eu", "registered_country_confidence",
            "registered_country_iso_code", "registered_country_geoname_id",
            "continent_name", "continent_names", "continent_locales",
            "continent_code", "continent_geoname_id", "time_zone", "accuracy_radius",
            "latitude", "longitude", "metro_code", "population_density", "locales"
        ]


    @cache_with_ttl(28800)
    def get(self, ip_address: str) -> dict:
        """
        Retrieves city-level geographical information for the given IP address.

        This method caches the results for 8 hours (28800 seconds) to improve
        performance and reduce the number of database lookups.

        Args:
            ip_address (str): The IP address to look up.

        Returns:
            dict: A dictionary containing city-level geographical information,
            including city name, postal code, country details, and more.
        """

        default = {key: None for key in self.fields}

        if not self.is_available or not isinstance(ip_address, str):
            return default

        try:
            city_location = self.reader.city(ip_address)

            return {
                # City
                "city_name": city_location.city.name,
                "city_names": city_location.city.names,
                "city_locales": city_location.city._locales,
                "city_confidence": city_location.city.confidence,
                "city_geoname_id": city_location.city.geoname_id,

                # Postal
                "postal_code": city_location.postal.code,
                "postal_confidence": city_location.postal.confidence,

                # Country
                "country_name": city_location.country.name,
                "country_names": city_location.country.names,
                "country_locales": city_location.country._locales,
                "country_is_in_eu": city_location.country.is_in_european_union,
                "country_confidence": city_location.country.confidence,
                "country_iso_code": city_location.country.iso_code,
                "country_geoname_id": city_location.country.geoname_id,

                # Registered Country
                "registered_country_name": city_location.registered_country.name,
                "registered_country_names": city_location.registered_country.names,
                "registered_country_locales": city_location.registered_country._locales,
                "registered_country_is_in_eu":
                    city_location.registered_country.is_in_european_union,
                "registered_country_confidence": city_location.registered_country.confidence,
                "registered_country_iso_code": city_location.registered_country.iso_code,
                "registered_country_geoname_id": city_location.registered_country.geoname_id,

                # Continent
                "continent_name": city_location.continent.name,
                "continent_names": city_location.continent.names,
                "continent_locales": city_location.continent._locales,
                "continent_code": city_location.continent.code,
                "continent_geoname_id": city_location.continent.geoname_id,

                # General Location Data
                "time_zone": city_location.location.time_zone,
                "accuracy_radius": city_location.location.accuracy_radius,
                "latitude": city_location.location.latitude,
                "longitude": city_location.location.longitude,
                "metro_code": city_location.location.metro_code,
                "population_density": city_location.location.population_density,
                "locales": city_location._locales
            }
        except (AddressNotFoundError, GeoIP2Error):
            pass

        return default


class ASNGeoIP(GeoIP):
    """
    A GeoIP implementation that retrieves Autonomous System Number (ASN) information.

    This class extends the GeoIP interface to provide detailed information about
    the Autonomous System associated with an IP address.

    Methods:
        get(ip_address: str) -> dict: Retrieves ASN-level information
        for the specified IP address.
    """


    @property
    def fields(self) -> list:
        return [
            "asn", "asorg", "network_is_global", "network_is_link_local",
            "network_is_loopback", "network_is_multicast", "network_is_private",
            "network_is_reserved", "network_is_unspecified"
        ]


    @cache_with_ttl(28800)
    def get(self, ip_address: str) -> dict:
        """
        Retrieves Autonomous System Number (ASN) information for the given IP address.

        This method provides details about the Autonomous System associated with
        the specified IP address, including the ASN and organization name.

        Args:
            ip_address (str): The IP address to look up.

        Returns:
            dict: A dictionary containing ASN-level information,
            including ASN number, organization name, and network characteristics.
        """

        keys = [
            "network_is_global", "network_is_link_local",
            "network_is_loopback", "network_is_multicast", "network_is_private",
            "network_is_reserved", "network_is_unspecified"
        ]

        default = {"asn": None, "asorg": None}
        default.update({key: False for key in keys})

        if not self.is_available or not isinstance(ip_address, str):
            return default

        try:
            autonomous_system = self.reader.asn(ip_address)

            return {
                # Autonomous System
                "asn": autonomous_system.autonomous_system_number,
                "asorg": autonomous_system.autonomous_system_organization,

                # Network
                "network_is_global": autonomous_system.network.is_global,
                "network_is_link_local": autonomous_system.network.is_link_local,
                "network_is_loopback": autonomous_system.network.is_loopback,
                "network_is_multicast": autonomous_system.network.is_multicast,
                "network_is_private": autonomous_system.network.is_private,
                "network_is_reserved": autonomous_system.network.is_reserved,
                "network_is_unspecified": autonomous_system.network.is_unspecified,
            }
        except (AddressNotFoundError, GeoIP2Error):
            pass

        return default


class AnonymousGeoIP(GeoIP):
    """
    A GeoIP implementation that retrieves information about anonymous IP addresses.

    This class extends the GeoIP interface to provide details on whether an IP
    address is associated with anonymity services, such as VPNs, proxies, or
    Tor exit nodes.

    Methods:
        get(ip_address: str) -> dict: Retrieves anonymity-related information
        for the specified IP address.
    """


    @property
    def fields(self) -> list:
        return [
            "is_anonymous", "is_anonymous_vpn", "is_hosting_provider",
            "is_public_proxy", "is_residential_proxy", "is_tor_exit_node"
        ]


    @cache_with_ttl(28800)
    def get(self, ip_address: str) -> dict:
        """
        Retrieves anonymity information for the given IP address.

        This method provides details about the anonymity status of the specified
        IP address, including whether it is associated with a VPN, public proxy,
        or Tor exit node.

        Args:
            ip_address (str): The IP address to look up.

        Returns:
            dict: A dictionary containfing anonymity-related information,
            including flags for anonymity, VPN usage, hosting provider status,
            public proxy status, residential proxy status, and Tor exit node status.
        """

        default = {key: False for key in self.fields}

        if not self.is_available or not isinstance(ip_address, str):
            return default

        try:
            anonymous = self.reader.anonymous_ip(ip_address)

            return {
                "is_anonymous": anonymous.is_anonymous,
                "is_anonymous_vpn": anonymous.is_anonymous_vpn,
                "is_hosting_provider": anonymous.is_hosting_provider,
                "is_public_proxy": anonymous.is_public_proxy,
                "is_residential_proxy": anonymous.is_residential_proxy,
                "is_tor_exit_node": anonymous.is_tor_exit_node
            }
        except (AddressNotFoundError, GeoIP2Error):
            pass

        return default


GEOIP_CLASSES: Final[dict] = {
    "city": CityGeoIP,
    "asn": ASNGeoIP,
    "anonymous": AnonymousGeoIP
}


def get_geoip() -> dict:
    """
    Retrieves and initializes GeoIP database instances.

    Returns:
        dict: A dictionary where the keys are the names of the GeoIP types 
              ('city', 'asn', 'anonymous') and the values are the initialized 
              instances of the corresponding GeoIP classes.
    """

    geoip = {}

    geoip_database_paths = download_geoip_databases()
    for db_name, db_class in GEOIP_CLASSES.items():
        file_path = geoip_database_paths.get(db_name, None)

        geoip[db_name] = db_class(file_path)

    return geoip
