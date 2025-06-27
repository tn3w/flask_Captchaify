from urllib.parse import urlparse
from typing import List, Optional

from flask import Request
from netaddr import IPAddress, AddrFormatError


def is_valid_routable_ip(ip: str) -> bool:
    """Check if the IP address is valid and routable."""
    try:
        ip_obj = IPAddress(ip)

        is_private = (ip_obj.version == 4 and ip_obj.is_ipv4_private_use()) or (
            ip_obj.version == 6 and ip_obj.is_ipv6_unique_local()
        )

        return not (
            is_private
            or ip_obj.is_loopback()
            or ip_obj.is_multicast()
            or ip_obj.is_reserved()
            or ip_obj.is_link_local()
        )
    except (AddrFormatError, ValueError):
        return False


def get_client_ip(request: Request) -> Optional[str]:
    """Get the client IP address from the request."""
    remote_ip = request.environ.get("REMOTE_ADDR")
    if remote_ip and remote_ip not in ["127.0.0.1", "::1"]:
        return remote_ip

    remote_ip_addresses = set()
    for header in [
        "HTTP_X_FORWARDED_FOR",
        "HTTP_X_REAL_IP",
        "HTTP_CF_CONNECTING_IP",
        "HTTP_X_FORWARDED",
    ]:
        if not (value := request.environ.get(header)):
            continue

        for ip in [ip.strip() for ip in value.split(",")]:
            if ip.startswith("[") and "]" in ip:
                remote_ip_addresses.add(ip[1 : ip.find("]")])
            elif ":" in ip and ip.count(":") == 1 and "::" not in ip:
                remote_ip_addresses.add(ip.split(":")[0])
            else:
                remote_ip_addresses.add(ip)

    valid_ipv4s: List[str] = []
    valid_ipv6s: List[str] = []

    for ip in remote_ip_addresses:
        if not is_valid_routable_ip(ip):
            continue

        ip_obj = IPAddress(ip)
        if ip_obj.version == 4:
            valid_ipv4s.append(ip)
        elif ip_obj.version == 6:
            valid_ipv6s.append(ip)

    if valid_ipv4s:
        return valid_ipv4s[0]
    if valid_ipv6s:
        return valid_ipv6s[0]

    return None


def get_return_url(request: Request) -> str:
    """Get the return URL from the request."""
    return_url = request.args.get(
        "return_url", request.form.get("return_url", "")
    ).strip()
    if not return_url:
        return "/"

    parsed_url = urlparse(return_url)
    if parsed_url.netloc or parsed_url.scheme:
        return "/"

    if return_url.count("?") == 1:
        return return_url.strip("?")

    return return_url
