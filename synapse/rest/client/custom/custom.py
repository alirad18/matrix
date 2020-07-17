from synapse.api.errors import Codes, LoginError, SynapseError
from synapse.api.ratelimiting import Ratelimiter
from synapse.http.server import finish_request
from synapse.http.servlet import (
    RestServlet,
    parse_json_object_from_request,
    parse_string,
)
from synapse.http.site import SynapseRequest
from synapse.rest.client.v2_alpha._base import client_patterns
from synapse.rest.well_known import WellKnownBuilder
from synapse.types import UserID
from synapse.util.msisdn import phone_number_to_msisdn
from synapse.storage._base import SQLBaseStore


class CustomRestServlet(RestServlet):
    PATTERNS = client_patterns("/custom$", v1=True)


    def __init__(self, hs):
        super(CustomRestServlet, self).__init__()
        self.hs = hs
        self.store = hs.get_datastore()
        self.jwt_enabled = hs.config.jwt_enabled
        self.jwt_secret = hs.config.jwt_secret
        self.jwt_algorithm = hs.config.jwt_algorithm
        self.saml2_enabled = hs.config.saml2_enabled
        self.cas_enabled = hs.config.cas_enabled
        self.oidc_enabled = hs.config.oidc_enabled
        self.auth_handler = self.hs.get_auth_handler()
        self.registration_handler = hs.get_registration_handler()
        self.handlers = hs.get_handlers()
        self._well_known_builder = WellKnownBuilder(hs)
        self._address_ratelimiter = Ratelimiter(
            clock=hs.get_clock(),
            rate_hz=self.hs.config.rc_login_address.per_second,
            burst_count=self.hs.config.rc_login_address.burst_count,
        )
        self._account_ratelimiter = Ratelimiter(
            clock=hs.get_clock(),
            rate_hz=self.hs.config.rc_login_account.per_second,
            burst_count=self.hs.config.rc_login_account.burst_count,
        )
        self._failed_attempts_ratelimiter = Ratelimiter(
            clock=hs.get_clock(),
            rate_hz=self.hs.config.rc_login_failed_attempts.per_second,
            burst_count=self.hs.config.rc_login_failed_attempts.burst_count,
        )

    async def on_POST(self, request):
        body = parse_json_object_from_request(request,True)
        await self.store.insert_custom_table(data=body['data'])
        return 200, "done"









def register_servlets(hs, http_server):
    CustomRestServlet(hs).register(http_server)

