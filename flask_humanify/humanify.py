from dataclasses import dataclass
import logging
from typing import List, Optional

from werkzeug.wrappers import Response
from flask import Blueprint, request, render_template, redirect, url_for, current_app
from .ipset import IPSetClient, ensure_server_running
from .utils import get_client_ip, get_return_url


VPN_PROVIDERS = [
    "NordVPN",
    "ProtonVPN",
    "ExpressVPN",
    "Surfshark",
    "PrivateInternetAccess",
    "CyberGhost",
    "TunnelBear",
    "Mullvad",
]

logger = logging.getLogger(__name__)


@dataclass
class HumanifyResult:
    """
    Result of the Humanify check.
    """

    ip: Optional[str] = None
    is_vpn: bool = False
    vpn_provider: Optional[str] = None
    is_proxy: bool = False
    is_datacenter: bool = False
    is_forum_spammer: bool = False
    is_firehol: bool = False
    is_tor_exit_node: bool = False
    is_invalid_ip: bool = False

    @property
    def is_bot(self) -> bool:
        """
        Check if the IP is a bot.
        """
        return (
            self.is_invalid_ip
            or self.is_vpn
            or self.is_proxy
            or self.is_datacenter
            or self.is_forum_spammer
            or self.is_firehol
            or self.is_tor_exit_node
        )

    @classmethod
    def from_ip_groups(cls, ip: str, ip_groups: List[str]) -> "HumanifyResult":
        """
        Create a HumanifyResult from a list of IP groups.
        """
        vpn_provider = next((name for name in VPN_PROVIDERS if name in ip_groups), None)

        result = HumanifyResult(
            ip=ip,
            is_vpn=vpn_provider is not None,
            vpn_provider=vpn_provider,
            is_proxy="FireholProxies" in ip_groups or "AwesomeProxies" in ip_groups,
            is_datacenter="Datacenter" in ip_groups,
            is_forum_spammer="StopForumSpam" in ip_groups,
            is_firehol="FireholLevel1" in ip_groups,
            is_tor_exit_node="TorExitNodes" in ip_groups,
        )
        return result

    def __bool__(self) -> bool:
        """
        Check if the IP is a bot.
        """
        return self.is_bot


class Humanify:
    """
    Protect against bots and DDoS attacks.
    """

    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Initialize the Humanify extension.
        """
        self.app = app

        ensure_server_running()
        self.ipset_client = IPSetClient()
        self.ipset_client.connect()

        self.blueprint = Blueprint(
            "humanify", __name__, template_folder="templates", static_folder="static"
        )
        self._register_routes()
        app.register_blueprint(self.blueprint)

    def _register_routes(self) -> None:
        """Register the humanify routes."""

        @self.blueprint.route("/humanify/access_denied", methods=["GET"])
        def access_denied():
            """
            Access denied route.
            """
            return (
                render_template("access_denied.html").replace(
                    "RETURN_URL", get_return_url(request)
                ),
                403,
                {"Cache-Control": "public, max-age=15552000"},
            )

    def register_middleware(self, action: str = "deny_access"):
        """
        Register the middleware.
        """

        self.app = self.app or current_app

        @self.app.before_request
        def before_request():
            """
            Before request hook.
            """
            if request.endpoint in ["humanify.rate_limited", "humanify.access_denied"]:
                return

            if self.is_bot:
                if action == "deny_access":
                    return self.deny_access()

    @property
    def is_bot(self) -> HumanifyResult:
        """
        Check if the IP is a bot.
        """
        ip = get_client_ip(request)
        if ip is None:
            return HumanifyResult(ip=ip, is_invalid_ip=True)
        ip_groups = self.ipset_client.lookup_ip(ip)
        return HumanifyResult.from_ip_groups(ip, ip_groups)

    def deny_access(self) -> Response:
        """
        Redirect to the access denied page.
        """
        return redirect(url_for("humanify.access_denied", return_url=request.full_path))
