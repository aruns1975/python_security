import logging

from security.exceptions import AuthorizationException
from security.inbound.context_holder import SecurityContextHolder
from security.inbound.policies import Policy
from security.inbound.principal import SecurityPrincipal

logger = logging.getLogger(__name__)


def authorize(policy: Policy) -> SecurityPrincipal:
    """Single enforcement point (AuthorizationManager) used by decorators and dependencies.

    Raises AuthenticationException (401) when anonymous, AuthorizationException (403) when denied.
    """
    principal = SecurityContextHolder.require_principal()
    if not policy(principal):
        logger.warning("Authorization denied", extra={"subject": principal.subject, "policy": policy.description})
        raise AuthorizationException()
    return principal
