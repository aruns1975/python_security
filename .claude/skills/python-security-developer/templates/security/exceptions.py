"""Security exception hierarchy.

Messages on these exceptions are returned to clients, so they must never
contain credentials, token contents or internal details.
"""


class SecurityException(Exception):
    """Base class for all framework security errors."""


class AuthenticationException(SecurityException):
    """Authentication failed or is required (HTTP 401)."""

    def __init__(self, message: str = "Authentication required", *, scheme: str = "Bearer") -> None:
        super().__init__(message)
        self.scheme = scheme


class AuthorizationException(SecurityException):
    """The authenticated identity lacks permission (HTTP 403)."""

    def __init__(self, message: str = "Access denied") -> None:
        super().__init__(message)


class OutboundSecurityException(SecurityException):
    """An outbound call violated security configuration (unknown service,
    foreign destination, caller-supplied credentials, plain HTTP...)."""


class OutboundServiceError(Exception):
    """A registered downstream service returned a non-success response or
    could not be reached. Carries no headers or credentials."""

    def __init__(self, service_id: str, status_code: int | None, message: str) -> None:
        super().__init__(f"{service_id}: {message}")
        self.service_id = service_id
        self.status_code = status_code
