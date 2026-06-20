__all__ = [
    "BrokerError",
    "NetworkError",
    "RequestTimeoutError",
    "DDoSProtectionError",
    "RateLimitExceededError",
    "AuthenticationError",
    "PermissionDeniedError",
    "InsufficientFundsError",
    "InsufficientHoldingsError",
    "InvalidOrderError",
    "OrderNotFoundError",
    "InputError",
    "ResponseError",
    "TokenDownloadError",
    "NotSupported",
]


class BrokerError(Exception):
    """Base class for all Fenix exceptions.

    Every error raised by Fenix derives from this class, so catching
    ``BrokerError`` catches any failure originating from the library. The
    optional keyword arguments capture the context of the failure and are
    stored as attributes of the same name for programmatic inspection.

    Attributes:
        message: Human-readable description of the error.
        broker: Identifier of the broker that raised the error.
        error_code: Broker-specific error code, when available.
        status_code: HTTP status code of the offending response, if any.
        payload: The decoded response body associated with the error.
        url: The request URL that triggered the error.
        method: The HTTP method of the offending request.
        response: The raw :class:`requests.Response` object, when available.
    """

    def __init__(
        self,
        message=None,
        *,
        broker=None,
        error_code=None,
        status_code=None,
        payload=None,
        url=None,
        method=None,
        response=None,
    ):
        """Initialize the error and record the failure context.

        Args:
            message: Human-readable description of the error.
            broker: Identifier of the broker that raised the error.
            error_code: Broker-specific error code, when available.
            status_code: HTTP status code of the offending response, if any.
            payload: The decoded response body associated with the error.
            url: The request URL that triggered the error.
            method: The HTTP method of the offending request.
            response: The raw :class:`requests.Response` object, when available.
        """
        self.message = message
        self.broker = broker
        self.error_code = error_code
        self.status_code = status_code
        self.payload = payload
        self.url = url
        self.method = method
        self.response = response
        if message is None:
            super().__init__()
        else:
            super().__init__(message)


class NetworkError(BrokerError):
    """Base class for networking errors"""
    pass


class RequestTimeoutError(NetworkError):
    """The request timed out."""
    pass


class DDoSProtectionError(NetworkError):
    """Triggered by broker's DDoS protection"""
    pass


class RateLimitExceededError(DDoSProtectionError):
    """Too many requests sent in a given amount of time. Corresponds to HTTP 429."""
    pass


class AuthenticationError(BrokerError):
    """The session is invalid or expired. Corresponds to HTTP 403 or API-specific auth errors."""
    pass


class PermissionDeniedError(BrokerError):
    """The user does not have permissions for the requested action."""
    pass


class InsufficientFundsError(BrokerError):
    """Not enough funds in the account for the requested action."""
    pass


class InsufficientHoldingsError(InsufficientFundsError):
    """Not enough holdings of a security for the requested action (e.g., selling stock you don't own)."""
    pass


class InvalidOrderError(BrokerError):
    """An order was rejected by the exchange because it's malformed."""
    pass


class OrderNotFoundError(InvalidOrderError):
    """The requested order does not exist."""
    pass


class InputError(BrokerError):
    """A generic error for malformed requests from the user's side (e.g., bad parameters). Corresponds to HTTP 400."""
    pass


class ResponseError(BrokerError):
    """Used when the broker's response is not in the expected format (e.g., failed JSON parsing)."""
    pass


class TokenDownloadError(ResponseError):
    """Specific error for failures during the token download process."""
    pass


class NotSupported(BrokerError):
    """
    Raised when a broker does not support a particular operation.

    Brokers advertise their supported operations via the ``has`` capability
    registry on :class:`fenix.base.broker.Broker`. Calling a method whose
    corresponding ``has`` entry is ``False`` raises this error.
    """
    pass
