import json
import logging
import socket
import time
import threading
import os
import urllib.request
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from netaddr import IPNetwork, IPAddress


logger = logging.getLogger(__name__)


class IPSetMemoryServer:
    """A singleton memory server that manages IP sets and provides lookup functionality."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, port: int = 9876, data_path: str = "ipset.json"):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(IPSetMemoryServer, cls).__new__(cls)
                cls._instance.initialized = False
            return cls._instance

    def __init__(self, port: int = 9876, data_path: str = "ipset.json"):
        if getattr(self, "initialized", False):
            return

        self.port = port
        self.data_path = data_path
        self.ip_to_groups: Dict[str, List[str]] = {}
        self.cidrs_to_ips: Dict[IPNetwork, List[str]] = {}
        self.last_update: Optional[datetime] = None
        self.server_socket = None
        self.server_thread = None
        self.running = False
        self.initialized = True

    def is_server_running(self) -> bool:
        """Check if the server is already running on the specified port."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", self.port))
                return True
        except (ConnectionRefusedError, socket.error):
            return False

    def download_data(self, force: bool = False) -> bool:
        """Download IP set data from GitHub and update the timestamp."""
        try:
            if not force and os.path.exists(self.data_path):
                with open(self.data_path, "r", encoding="utf-8") as f:
                    try:
                        data = json.load(f)
                        if isinstance(data, dict) and "_timestamp" in data:
                            timestamp = datetime.fromisoformat(data["_timestamp"])
                            if datetime.now() - timestamp < timedelta(days=7):
                                return True
                    except (json.JSONDecodeError, KeyError, ValueError):
                        pass

            url = "https://raw.githubusercontent.com/tn3w/IPSet/refs/heads/master/ipset.json"
            with urllib.request.urlopen(url, timeout=30) as response:
                response_data = response.read().decode("utf-8")

            data = json.loads(response_data)
            data["_timestamp"] = datetime.now().isoformat()

            with open(self.data_path, "w", encoding="utf-8") as f:
                json.dump(data, f)

            return True
        except Exception as e:
            logger.error("Error downloading IP set data: %s", e)
            return False

    def load_data(self) -> bool:
        """Load IP set data into memory."""
        try:
            with open(self.data_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if "_timestamp" in data:
                self.last_update = datetime.fromisoformat(data.pop("_timestamp"))

            self.ip_to_groups = {}
            self.cidrs_to_ips = {}

            for group, ips in data.items():
                for ip in ips:
                    if "/" in ip:
                        try:
                            ip_obj = IPNetwork(ip)
                            if ip_obj not in self.cidrs_to_ips:
                                self.cidrs_to_ips[ip_obj] = []
                            self.cidrs_to_ips[ip_obj].append(group)
                        except Exception:
                            continue
                        continue

                    if ip not in self.ip_to_groups:
                        self.ip_to_groups[ip] = []
                    self.ip_to_groups[ip].append(group)

            return True
        except Exception as e:
            logger.error("Error loading IP set data: %s", e)
            return False

    def check_and_update_data(self) -> None:
        """Check if data needs updating and update if necessary."""
        if self.last_update is None or datetime.now() - self.last_update > timedelta(
            days=7
        ):
            threading.Thread(target=self._async_update).start()

    def _async_update(self) -> None:
        """Update data in the background without affecting current operations."""
        if self.download_data(force=True):
            self.load_data()

    def find_matching_groups(self, ip: str) -> List[str]:
        """Find all groups matching the given IP."""
        self.check_and_update_data()

        matching_groups = self.ip_to_groups.get(ip, [])

        try:
            ip_obj = IPAddress(ip)
            ip_version = ip_obj.version

            for cidr, groups in self.cidrs_to_ips.items():
                if cidr.version != ip_version:
                    continue

                if ip_obj in cidr:
                    for group in groups:
                        if group not in matching_groups:
                            matching_groups.append(group)

        except Exception:
            return []

        return matching_groups

    def handle_client(
        self, client_socket: socket.socket, addr: Tuple[str, int]
    ) -> None:
        """Handle client connection and queries."""
        try:
            while True:
                data = client_socket.recv(1024).decode("utf-8").strip()
                if not data:
                    break

                result = self.find_matching_groups(data)
                response = json.dumps(result)
                client_socket.send(f"{response}\n".encode("utf-8"))
        except Exception as e:
            logger.error("Error handling client %s: %s", addr, e)
        finally:
            client_socket.close()

    def run_server(self) -> None:
        """Run the memory server."""
        if self.is_server_running():
            logger.info("Server already running on port %s", self.port)
            return

        if not os.path.exists(self.data_path):
            logger.info("IP data file not found at %s, downloading...", self.data_path)
            if not self.download_data():
                logger.error("Failed to download data, cannot start server")
                return

        if not self.load_data():
            logger.error("Failed to load data, cannot start server")
            return

        self.check_and_update_data()
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(10)
            self.running = True

            logger.info(
                "Memory server started on port %s with data from %s",
                self.port,
                self.data_path,
            )

            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client, args=(client_socket, addr)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    if self.running:
                        logger.error("Error accepting connection: %s", e)

        except Exception as e:
            logger.error("Server error: %s", e)
        finally:
            if self.server_socket:
                self.server_socket.close()

    def start(self) -> None:
        """Start the server in a background thread."""
        if self.server_thread and self.server_thread.is_alive():
            return

        self.server_thread = threading.Thread(target=self.run_server)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self) -> None:
        """Stop the server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()


class IPSetClient:
    """Client to connect to the IPSetMemoryServer."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9876):
        self.host = host
        self.port = port
        self.socket = None

    def connect(self) -> bool:
        """Connect to the memory server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            return True
        except Exception as e:
            logger.error("Failed to connect to memory server: %s", e)
            return False

    def lookup_ip(self, ip: str) -> List[str]:
        """Look up an IP in the memory server."""
        if not self.socket:
            if not self.connect():
                return []

        try:
            if self.socket:
                self.socket.send(f"{ip}\n".encode("utf-8"))
                response = self.socket.recv(4096).decode("utf-8").strip()
                return json.loads(response)
            return []
        except Exception as e:
            logger.error("Error looking up IP: %s", e)
            if self.connect():
                try:
                    if self.socket:
                        self.socket.send(f"{ip}\n".encode("utf-8"))
                        response = self.socket.recv(4096).decode("utf-8").strip()
                        return json.loads(response)
                except Exception:
                    pass
            return []

    def close(self) -> None:
        """Close the connection to the memory server."""
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None


def ensure_server_running(port: int = 9876, data_path: str = "ipset.json") -> None:
    """Ensure that the memory server is running."""
    server = IPSetMemoryServer(port=port, data_path=data_path)
    server.start()

    while not server.is_server_running():
        time.sleep(0.1)
