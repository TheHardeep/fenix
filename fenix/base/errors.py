__all__ = [
    "InputError",
    "ResponseError",
    "TokenDownloadError",
    "RequestTimeout",
    "NetworkError",
    "BrokerError"
]


class InputError(Exception):
    pass


class ResponseError(Exception):
    pass


class TokenDownloadError(Exception):
    pass


class RequestTimeout(Exception):
    pass


class NetworkError(Exception):
    pass


class BrokerError(Exception):
    pass
