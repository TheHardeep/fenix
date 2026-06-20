from __future__ import annotations
from copy import deepcopy
from datetime import datetime
from json import dumps, loads
from ssl import SSLError

from typing import Any, Callable, Mapping, NamedTuple, NoReturn, Optional, TYPE_CHECKING, TypeVar
from pyotp import TOTP
from re import compile
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import logging
import threading
import time

from requests.sessions import session as req_session
from requests.models import Response
from requests.exceptions import HTTPError
from requests.exceptions import Timeout
from requests.exceptions import TooManyRedirects
from requests.exceptions import RequestException
from requests.exceptions import ConnectionError as RequestsConnectionError

from fenix.base.constants import Side
from fenix.base.constants import Root
from fenix.base.constants import OrderType
from fenix.base.constants import Product
from fenix.base.constants import Validity
from fenix.base.constants import Variety

from fenix.base.errors import (
    AuthenticationError,
    BrokerError,
    InputError,
    NetworkError,
    NotSupported,
    PermissionDeniedError,
    RateLimitExceededError,
    RequestTimeoutError,
    ResponseError,
)

from fenix.paper.client import PaperExecutionClient

from contextlib import ExitStack

__all__ = [
    "Broker",
]


_REDACTED = "***"
_DEFAULT_SENSITIVE_LOG_KEYS = {
    "authorization",
    "proxy_authorization",
    "x_api_key",
    "api_key",
    "apikey",
    "api_secret",
    "secret",
    "password",
    "passwd",
    "pwd",
    "pin",
    "totp",
    "otp",
    "cookie",
    "set_cookie",
    "token",
    "access_token",
    "refresh_token",
    "request_token",
    "session_token",
    "jwt_token",
    "AccessToken",
    "ID",
}


# ─────────────────────────────────────────────────────────────────────────────
# Convenience order-method factory
# ─────────────────────────────────────────────────────────────────────────────
#
# Each :class:`_OrderVariant` in ``_ORDER_VARIANTS`` describes one dynamically
# generated convenience method on :class:`Broker`:
#
#   • ``side = None``    →  side-agnostic; caller must supply ``side``
#   • ``price = None``   →  caller must supply ``price``   (e.g. limit orders)
#   • ``trigger = None`` →  caller must supply ``trigger`` (e.g. SL orders)
#   • A concrete value   →  baked in; never exposed to the caller
#
# ``_with_order_methods`` is applied as a decorator to :class:`Broker` so the
# installation is co-located with the class declaration. The TYPE_CHECKING
# block inside :class:`Broker` mirrors these signatures exactly so that
# language servers (Pylance / Pyright / mypy) can provide full autocomplete
# and type-checking without any runtime cost.
#
# Each generated method consults ``self.has[method_name]`` at call time and
# raises :class:`NotSupported` if the broker has disabled it. Subclasses can
# override capabilities by declaring their own ``has`` dict — it is
# automatically merged with the parent's dict in ``__init_subclass__``.
# ─────────────────────────────────────────────────────────────────────────────


class _OrderVariant(NamedTuple):
    """One row describing a dynamically generated order method."""

    name: str
    side: Optional[str]
    price: Optional[float]
    trigger: Optional[float]
    variety: str


_ORDER_VARIANTS: list[_OrderVariant] = [
    # ── Side-specific ─────────────────────────────────────────────────────────
    _OrderVariant("market_buy_order",   Side.BUY,  0.0,  0.0,  Variety.REGULAR),
    _OrderVariant("market_sell_order",  Side.SELL, 0.0,  0.0,  Variety.REGULAR),
    _OrderVariant("limit_buy_order",    Side.BUY,  None, 0.0,  Variety.REGULAR),
    _OrderVariant("limit_sell_order",   Side.SELL, None, 0.0,  Variety.REGULAR),
    _OrderVariant("sl_buy_order",       Side.BUY,  None, None, Variety.STOPLOSS),
    _OrderVariant("sl_sell_order",      Side.SELL, None, None, Variety.STOPLOSS),
    _OrderVariant("slm_buy_order",      Side.BUY,  0.0,  None, Variety.STOPLOSS),
    _OrderVariant("slm_sell_order",     Side.SELL, 0.0,  None, Variety.STOPLOSS),
    # ── Side-agnostic (caller supplies ``side``) ──────────────────────────────
    _OrderVariant("market_order",       None,      0.0,  0.0,  Variety.REGULAR),
    _OrderVariant("limit_order",        None,      None, 0.0,  Variety.REGULAR),
    _OrderVariant("sl_order",           None,      None, None, Variety.STOPLOSS),
    _OrderVariant("slm_order",          None,      0.0,  None, Variety.STOPLOSS),
]


_BrokerClass = TypeVar("_BrokerClass", bound=type)
_UNSET = object()


def _make_order_method(
    variant: _OrderVariant,
) -> Callable[..., dict[Any, Any]]:
    """
    Return a convenience order method with the parameters from ``variant``
    baked in.

    Parameters left as ``None`` on the variant are forwarded from the
    caller's arguments; concrete values are fixed and the caller never
    needs to supply them. The ``TYPE_CHECKING`` stubs inside
    :class:`Broker` mirror each variant's exposed parameters exactly.
    """

    fixed_side = variant.side
    fixed_price = variant.price
    fixed_trigger = variant.trigger
    default_variety = variant.variety
    method_name = variant.name

    def order_method(
        self,
        token_dict: dict,
        quantity: int,
        unique_id: str,
        side: Any = _UNSET,
        price: Any = _UNSET,
        trigger: Any = _UNSET,
        target: float = 0.0,
        stoploss: float = 0.0,
        trailing_sl: float = 0.0,
        product: str = Product.MIS,
        validity: str = Validity.DAY,
        variety: str = default_variety,
    ) -> dict[Any, Any]:
        if not self.has.get(method_name, True):
            raise NotSupported(
                f"{self.__class__.__name__} does not support {method_name}()."
            )

        if fixed_side is None:
            if side is _UNSET:
                raise TypeError(
                    f"{method_name}() missing required argument: 'side'"
                )
            resolved_side = side
        else:
            if side is not _UNSET:
                raise TypeError(
                    f"{method_name}() got an unexpected argument: 'side'"
                )
            resolved_side = fixed_side

        if fixed_price is None:
            if price is _UNSET:
                raise TypeError(
                    f"{method_name}() missing required argument: 'price'"
                )
            resolved_price = price
        else:
            if price is not _UNSET:
                raise TypeError(
                    f"{method_name}() got an unexpected argument: 'price'"
                )
            resolved_price = fixed_price

        if fixed_trigger is None:
            if trigger is _UNSET:
                raise TypeError(
                    f"{method_name}() missing required argument: 'trigger'"
                )
            resolved_trigger = trigger
        else:
            if trigger is not _UNSET:
                raise TypeError(
                    f"{method_name}() got an unexpected argument: 'trigger'"
                )
            resolved_trigger = fixed_trigger

        return self.place_order(
            token_dict=token_dict,
            quantity=quantity,
            side=resolved_side,
            product=product,
            validity=validity,
            variety=variety,
            unique_id=unique_id,
            price=resolved_price,
            trigger=resolved_trigger,
            target=target,
            stoploss=stoploss,
            trailing_sl=trailing_sl,
        )

    return order_method


def _with_order_methods(cls: _BrokerClass) -> _BrokerClass:
    """
    Class decorator that installs the convenience order methods described by
    :data:`_ORDER_VARIANTS` onto ``cls``.

    The decorator runs once, immediately after the class body finishes
    executing, which is why it is safe to use ``setattr`` — by that point
    ``cls`` exists as a fully-defined class object.
    """
    for variant in _ORDER_VARIANTS:
        method = _make_order_method(variant)
        method.__name__ = variant.name
        method.__qualname__ = f"{cls.__name__}.{variant.name}"
        method.__doc__ = (
            f"Convenience wrapper around :meth:`{cls.__name__}.place_order`.\n\n"
            f"Baked-in defaults — "
            f"side: {variant.side!r}, "
            f"price: {variant.price!r}, "
            f"trigger: {variant.trigger!r}, "
            f"variety: {variant.variety!r}.\n\n"
            f"Parameters shown as ``None`` above must be supplied by the caller.\n"
            f"Raises :class:`fenix.base.errors.NotSupported` if "
            f"``self.has[{variant.name!r}]`` is ``False``."
        )
        setattr(cls, variant.name, method)
    return cls


@_with_order_methods
class Broker:
    """Base Class Common to All Brokers"""

    expiry_dates = {}
    cookies = {}
    _API = {}
    STANDARD_MAPS = {}
    REQUEST_MAPS = {}

    # Keys that must be present in a header dict passed to ``use_headers``.
    # Subclasses override this tuple with the specific keys their authenticated
    # API requires.
    _REQUIRED_AUTH_HEADER_KEYS: tuple[str, ...] = ()
    _AUTH_CONTEXT_KEYS: tuple[str, ...] = ()

    # Capability registry. Every generated convenience method checks
    # ``self.has[<method_name>]`` before delegating to ``place_order``.
    # Subclasses override this by declaring their own ``has`` dict with only
    # the keys they want to change — ``__init_subclass__`` merges it with the
    # parent's dict automatically, so subclasses do not need to re-declare
    # every capability.
    has: dict[str, bool] = {
        "place_order": True,
        **{variant.name: True for variant in _ORDER_VARIANTS},
    }

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """
        Merge the subclass's ``has`` dict with its parent's, so subclasses
        only need to declare the capabilities they change.
        """
        super().__init_subclass__(**kwargs)
        parent_has: dict[str, bool] = {}
        for base in cls.__mro__[1:]:
            base_has = base.__dict__.get("has")
            if isinstance(base_has, dict):
                parent_has = base_has
                break

        own_has = cls.__dict__.get("has")
        if isinstance(own_has, dict):
            cls.has = {**parent_has, **own_has}
        else:
            cls.has = dict(parent_has)

    NFO_URL = "https://www.nseindia.com/api/option-chain-indices"
    BFO_URL = "https://api.bseindia.com/BseIndiaAPI/api/ddlExpiry_IV/w"
    nfo_url = "https://www.nseindia.com/api/option-chain-indices"
    bfo_url = "https://api.bseindia.com/BseIndiaAPI/api/ddlExpiry_IV/w"

    def __init__(self, config: dict | None = None):
        """Initialize the broker from its ``describe()`` metadata.

        Merges ``describe()`` with the optional ``config`` overrides, then sets
        up logging/redaction options, the per-instance ``_API`` copy, the HTTP
        session, the rate-limit token buckets, and (when ``paper_mode`` is
        enabled) the paper-trading client.

        Args:
            config: Optional overrides merged on top of ``describe()``. Keys
                matching instance attributes are also applied directly;
                ``sensitiveLogKeys`` and ``sensitiveLogKeysIncludeDefault`` are
                consumed via ``describe()`` and skipped here.
        """
        description = self.describe()
        if config:
            description = {**description, **config}

        self.id = description.get('id', 'Broker')
        self.tokenParams = description.get("tokenParams", {})
        self.enableRateLimit = description.get('enableRateLimit', True)
        self.rateLimits = description.get('rateLimits', {})
        self.logger = description.get("logger") or logging.getLogger(__name__)
        self.verbose = bool(description.get("verbose", False))
        self.returnResponseHeaders = bool(
            description.get("returnResponseHeaders", False)
        )
        self.enableLastHttpResponse = bool(
            description.get("enableLastHttpResponse", True)
        )
        self.enableLastJsonResponse = bool(
            description.get("enableLastJsonResponse", False)
        )
        self.enableLastResponseHeaders = bool(
            description.get("enableLastResponseHeaders", True)
        )
        self.logSensitive = bool(description.get("logSensitive", False))
        self.sensitiveLogKeysIncludeDefault = bool(
            description.get("sensitiveLogKeysIncludeDefault", True)
        )
        self.sensitiveLogKeys = self._build_sensitive_log_keys(description)
        self.maxLogBodyLength = description.get("maxLogBodyLength")
        self.last_http_response = None
        self.last_json_response = None
        self.last_response_headers = None
        self.last_request_headers = None
        self.last_request_body = None
        self.last_request_params = None
        self.last_request_url = None
        self.last_request_method = None
        self.last_response_url = None
        self.last_paper_request = None
        self.last_paper_response = None
        self.last_paper_interaction = None
        self.rate_limit_padding = 1.1
        self.proxies = description.get("proxies", {})
        # Adapters that rewrite endpoints at runtime (e.g. Symphony resolving
        # its dynamic Interactive base via HostLookup) must not clobber the
        # host used by other instances of the same broker. The only such
        # mutation across all adapters targets ``_API["servers"]``, so give
        # each instance a private shallow copy of the ``_API`` shell plus its
        # own ``servers`` dict, while the larger read-only ``paths`` map stays
        # shared with the class. (If a future adapter mutates another ``_API``
        # sub-dict at runtime, deep-copy that sub-dict here too.)
        cls_api = type(self)._API
        self._API = dict(cls_api)
        if "servers" in cls_api:
            self._API["servers"] = deepcopy(cls_api["servers"])
        self._headers = None
        self._auth_context = {}
        self.token_json = {"Equity": {}, "Futures": {}, "Options": {}, "Indices": {}}
        self.alltoken_json = {}

        if config:
            for key, value in config.items():
                if key in {"sensitiveLogKeys", "sensitiveLogKeysIncludeDefault"}:
                    continue
                if hasattr(self, key):
                    setattr(self, key, value)

        # Paper-mode runtime setup. Reads from the merged ``description``
        # so values supplied via ``config`` win over ``describe()`` defaults
        # (the merge happens at the top of ``__init__``). Subclasses do not
        # need to touch this — they only add the ``authenticate()`` short-
        # circuit and per-method ``if self.paper_mode and self._paper is
        # not None`` guards.
        self.paper_mode: bool = bool(description.get("paper_mode", False))
        self._paper: PaperExecutionClient | None = None
        if self.paper_mode:
            paper_client_id = description.get("paper_client_id", "PAPER001")
            self._paper = PaperExecutionClient(
                broker_id=self.id,
                client_id=paper_client_id,
                starting_margin=description.get(
                    "paper_starting_margin",
                    1_000_000.0,
                ),
                reject_invalid_stops=description.get(
                    "paper_reject_invalid_stops",
                    True,
                ),
                logger=self.logger,
                verbose=self.verbose,
                log_hook=self.log,
                format_log_value=self._format_log_value,
                interaction_hook=self._record_paper_interaction,
                max_interactions=description.get(
                    "paper_log_history_size",
                    description.get("paperInteractionLogSize", 100),
                ),
            )
            # Pre-seed any keys this broker stores on ``_auth_context``
            # (e.g. ``user_id``) so methods that read them before
            # ``authenticate()`` is called don't KeyError.
            if self._AUTH_CONTEXT_KEYS:
                self._auth_context = {
                    key: paper_client_id for key in self._AUTH_CONTEXT_KEYS
                }

        self._session = self._create_session()
        self._token_buckets = {}
        self._bucket_locks = {}

        if self.enableRateLimit:
            for group, all_params in self.rateLimits.items():

                params_list = all_params if isinstance(
                    all_params, list) else [all_params]

                for params in params_list:
                    period = params['period']
                    capacity = params['capacity']
                    cost = params.get('cost', 1.0)

                    bucket_name = f"{group}_{int(period)}s"

                    self._token_buckets[bucket_name] = {
                        'tokens': float(capacity),
                        # tokens per second
                        'refill_rate': float(capacity) / period,
                        'capacity': float(capacity),
                        'cost': cost,
                        'last_refill_time': time.monotonic(),
                    }

                    self._bucket_locks[bucket_name] = threading.Lock()

    def on_tick(
        self,
        token: int,
        ltp: float | None = None,
        bid: float | None = None,
        ask: float | None = None,
    ) -> list[dict[str, Any]]:
        """Push a market-data tick into the paper-trading engine.

        Only valid when the broker was constructed with ``paper_mode=True``.
        Returns the orders that filled as a result of this tick so callers
        can react (log, emit, etc.).

        Args:
            token: Instrument token the tick belongs to.
            ltp: Last traded price.
            bid: Best bid (optional, reserved for richer matching later).
            ask: Best ask (optional, reserved for richer matching later).

        Returns:
            Orders newly moved to ``Status.FILLED`` on this tick.

        Raises:
            InputError: If the broker is not in paper mode.
        """
        if not self.paper_mode or self._paper is None:
            raise InputError(
                f"{self.id}.on_tick() is only valid when paper_mode=True."
            )
        return self._paper.on_tick(token=token, ltp=ltp, bid=bid, ask=ask)

    def describe(self) -> dict[str, Any]:
        """
        Child classes MUST implement this method to describe their properties.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement the describe() method."
        )

    def get_url(self, endpoint_name: str) -> str:
        """Build the full request URL for a named API endpoint.

        Looks ``endpoint_name`` up in ``self._API['paths']``. A string entry is
        returned as-is; a ``{'server', 'path'}`` entry is joined against the
        matching host in ``self._API['servers']``.

        Args:
            endpoint_name: Key in ``_API['paths']`` (e.g. ``"place_order"``).

        Returns:
            The fully-qualified request URL.

        Raises:
            ValueError: If ``endpoint_name`` is not defined in ``_API['paths']``.
        """
        path_info = self._API['paths'].get(endpoint_name)

        if not path_info:
            raise ValueError(
                f"Endpoint '{endpoint_name}' not found in API definition.")

        if isinstance(path_info, str):
            return path_info

        server_key = path_info['server']
        base_url = self._API['servers'][server_key]
        relative_path = path_info['path']
        # print(f"{base_url}{relative_path}")
        return f"{base_url}{relative_path}"

    def _format_for_broker(
            self,
            map_name: str,
            fenix_value: Any,
            raise_error: bool = True) -> Any:
        """
        Translates a Fenix constant into the string format the broker's API expects.
        Includes built-in validation to raise an error for invalid user input.

        Args:
            map_name (str): The name of the map to use (e.g., 'side', 'product').
            fenix_value (Any): The Fenix constant provided by the user (e.g., Side.BUY).
            raise_error (bool): If True, raises InputError for invalid fenix_value.
                                If False, returns the value as-is.
        """
        mapping = self.REQUEST_MAPS.get(map_name)
        if not mapping:
            # This is a developer error, not a user error.
            raise ValueError(f"Request map '{map_name}' does not exist.")

        broker_value = mapping.get(fenix_value)

        if broker_value is not None:
            # The value was found, return the translation
            return broker_value

        # --- The value was NOT found in the map ---
        if raise_error:
            # Get the list of valid Fenix constants from the map's keys
            possible_values = list(mapping.keys())
            # Raise a descriptive error, similar to the old _key_mapper
            raise InputError(
                f"Invalid value for '{map_name}': '{fenix_value}'. "
                f"Possible values are: {possible_values}"
            )
        else:
            # If error raising is disabled, just return the original value
            return fenix_value

    def _parse_from_broker(
            self,
            map_name: str,
            broker_value: str,
            default: Any = None) -> Any:
        """Translates a value received from the broker's API into a Fenix constant."""
        return self.STANDARD_MAPS[map_name].get(
            broker_value, default or broker_value)

    def __repr__(self) -> str:
        """Return the ``fenix.<id>()`` representation of the broker."""
        return f"fenix.{self.id}()"

    @staticmethod
    def _resolve_order_type(price: float, trigger: float) -> str:
        """Infer the order type from the price and trigger fields.

        Args:
            price: Limit price; falsy (``0``) means no price was supplied.
            trigger: Trigger price; falsy (``0``) means no trigger was supplied.

        Returns:
            One of ``OrderType.MARKET``, ``OrderType.LIMIT``, ``OrderType.SL``
            or ``OrderType.SLM`` depending on which fields are present.
        """
        if not price and trigger:
            return OrderType.SLM
        if not price:
            return OrderType.MARKET
        if not trigger:
            return OrderType.LIMIT
        return OrderType.SL

    @staticmethod
    def _format_strike(value: Any) -> str:
        """Normalise an option strike price to a clean string.

        The value is parsed as a float and rendered without redundant
        trailing zeros, so ``104.0`` becomes ``"104"`` while ``104.75`` is
        preserved as ``"104.75"``. Some instrument masters carry a negative
        sentinel (e.g. ``-0.01``) in the strike column for non-option rows
        such as futures; those are normalised to an empty string. Values
        that cannot be parsed as a float are returned unchanged via
        ``str()``.

        Args:
            value: Raw strike value from an instrument master (str, int,
                float, or other).

        Returns:
            The strike formatted as a clean string.
        """
        try:
            strike = float(value)
        except (TypeError, ValueError):
            return str(value)

        if strike < 0:
            return ""
        if strike == int(strike):
            return str(int(strike))
        return ("%f" % strike).rstrip("0").rstrip(".")

    @staticmethod
    def _validate_order_inputs(
            quantity: int,
            price: float = 0.0,
            trigger: float = 0.0,
            target: float = 0.0,
            stoploss: float = 0.0,
            trailing_sl: float = 0.0) -> None:
        """Validate quantity and price-like order inputs.

        Args:
            quantity: Order quantity; must be greater than 0.
            price: Limit price; must be non-negative.
            trigger: Trigger price; must be non-negative.
            target: Target price; must be non-negative.
            stoploss: Stop-loss price; must be non-negative.
            trailing_sl: Trailing stop-loss; must be non-negative.

        Raises:
            InputError: If ``quantity`` is not positive or any other field is
                negative.
        """
        if quantity <= 0:
            raise InputError("Order quantity must be greater than 0.")

        non_negative_inputs = {
            "price": price,
            "trigger": trigger,
            "target": target,
            "stoploss": stoploss,
            "trailing_sl": trailing_sl,
        }

        for field_name, value in non_negative_inputs.items():
            if value < 0:
                raise InputError(f"Order {field_name} must be non-negative.")

    def place_order(
            self,
            token_dict: dict,
            quantity: int,
            side: str,
            product: str,
            validity: str,
            variety: str,
            unique_id: str,
            price: float = 0.0,
            trigger: float = 0.0,
            target: float = 0.0,
            stoploss: float = 0.0,
            trailing_sl: float = 0.0) -> dict[Any, Any]:
        """Place an order through the broker.

        Abstract method; each concrete broker implements the API call. The
        convenience wrappers (``market_order``, ``limit_order``, ``sl_order``,
        etc.) ultimately delegate here.

        Args:
            token_dict: Instrument record (from the broker's token maps) for the
                contract to trade.
            quantity: Order quantity.
            side: Order side in Fenix format (``Side.BUY`` / ``Side.SELL``).
            product: Product type in Fenix format (e.g. ``Product.MIS``).
            validity: Order validity in Fenix format (e.g. ``Validity.DAY``).
            variety: Order variety in Fenix format (e.g. ``Variety.REGULAR``).
            unique_id: Caller-supplied identifier echoed back on the order.
            price: Limit price. Defaults to 0.0.
            trigger: Trigger price for stop orders. Defaults to 0.0.
            target: Target price for bracket orders. Defaults to 0.0.
            stoploss: Stop-loss price for bracket orders. Defaults to 0.0.
            trailing_sl: Trailing stop-loss for bracket orders. Defaults to 0.0.

        Returns:
            The placed order as a unified Fenix order record.

        Raises:
            NotImplementedError: If the broker does not implement ``place_order``.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement place_order()."
        )

    if TYPE_CHECKING:
        # ── Side-specific convenience methods ──────────────────────────
        # Generated at runtime by _make_order_method / setattr below the
        # class body. Declared here so language servers can discover them.

        def market_buy_order(self, token_dict: dict, quantity: int, unique_id: str, *, target: float = ..., stoploss: float = ..., trailing_sl: float = ..., product: str = ..., validity: str = ..., variety: str = ...) -> dict[Any, Any]: ...
        def market_sell_order(self, token_dict: dict, quantity: int, unique_id: str, *, target: float = ..., stoploss: float = ..., trailing_sl: float = ..., product: str = ..., validity: str = ..., variety: str = ...) -> dict[Any, Any]: ...
        def limit_buy_order(self, token_dict: dict, quantity: int, unique_id: str, *, price: float, target: float = ..., stoploss: float = ..., trailing_sl: float = ..., product: str = ..., validity: str = ..., variety: str = ...) -> dict[Any, Any]: ...
        def limit_sell_order(self, token_dict: dict, quantity: int, unique_id: str, *, price: float, target: float = ..., stoploss: float = ..., trailing_sl: float = ..., product: str = ..., validity: str = ..., variety: str = ...) -> dict[Any, Any]: ...
        def sl_buy_order(self, token_dict: dict, quantity: int, unique_id: str, *, price: float, trigger: float, target: float = ..., stoploss: float = ..., trailing_sl: float = ..., product: str = ..., validity: str = ..., variety: str = ...) -> dict[Any, Any]: ...
        def sl_sell_order(self, token_dict: dict, quantity: int, unique_id: str, *, price: float, trigger: float, target: float = ..., stoploss: float = ..., trailing_sl: float = ..., product: str = ..., validity: str = ..., variety: str = ...) -> dict[Any, Any]: ...
        def slm_buy_order(self, token_dict: dict, quantity: int, unique_id: str, *, trigger: float, target: float = ..., stoploss: float = ..., trailing_sl: float = ..., product: str = ..., validity: str = ..., variety: str = ...) -> dict[Any, Any]: ...
        def slm_sell_order(self, token_dict: dict, quantity: int, unique_id: str, *, trigger: float, target: float = ..., stoploss: float = ..., trailing_sl: float = ..., product: str = ..., validity: str = ..., variety: str = ...) -> dict[Any, Any]: ...

        # ── Side-agnostic convenience methods (pass side as a parameter) ──
        def market_order(self, token_dict: dict, quantity: int, side: str, unique_id: str, *, target: float = ..., stoploss: float = ..., trailing_sl: float = ..., product: str = ..., validity: str = ..., variety: str = ...) -> dict[Any, Any]: ...
        def limit_order(self, token_dict: dict, quantity: int, side: str, unique_id: str, *, price: float, target: float = ..., stoploss: float = ..., trailing_sl: float = ..., product: str = ..., validity: str = ..., variety: str = ...) -> dict[Any, Any]: ...
        def sl_order(self, token_dict: dict, quantity: int, side: str, unique_id: str, *, price: float, trigger: float, target: float = ..., stoploss: float = ..., trailing_sl: float = ..., product: str = ..., validity: str = ..., variety: str = ...) -> dict[Any, Any]: ...
        def slm_order(self, token_dict: dict, quantity: int, side: str, unique_id: str, *, trigger: float, target: float = ..., stoploss: float = ..., trailing_sl: float = ..., product: str = ..., validity: str = ..., variety: str = ...) -> dict[Any, Any]: ...

    @staticmethod
    def _create_session():
        """
        Creates a requests Session.

        Returns:
            requests.sessions.Session: A new requests Session object.
        """
        return req_session()

    def reset_session(self) -> None:
        """Discard the current HTTP session and create a fresh one.

        Useful after restoring stored auth headers (so the new session is not
        polluted by cookies from a previous user), after a token refresh, or
        when recovering from a connection-pool error.
        """
        self._session = self._create_session()

    def use_headers(
        self,
        headers: dict[str, str],
        reset_session: bool = False,
        auth_params: Mapping[str, Any] | None = None,
    ) -> dict[str, str]:
        """Use a previously authenticated header set on this broker instance.

        Validates that the supplied dict contains every key listed in
        ``_REQUIRED_AUTH_HEADER_KEYS``, stores the request headers on
        ``self._headers``, stores any keys listed in ``_AUTH_CONTEXT_KEYS`` on
        ``self._auth_context``, and optionally rebuilds the underlying HTTP
        session.

        Subclasses should override ``_REQUIRED_AUTH_HEADER_KEYS`` (and only
        override this method when restoring headers needs additional work,
        such as re-deriving a checksum or refreshing a token).

        Args:
            headers: Authenticated headers to store on this instance.
            reset_session: Whether to rebuild the HTTP session after storing
                the headers.
            auth_params: Optional login/authentication parameters to preserve
                for brokers that need non-header auth context, such as a
                client id used in request payloads.

        Returns:
            The reusable authenticated header set, including any stored auth
            context keys. ``self._headers`` itself contains request headers
            only.

        Raises:
            KeyError: If any required authentication header is missing.
        """
        missing_keys = [
            key for key in self._REQUIRED_AUTH_HEADER_KEYS
            if key not in headers
        ]
        if missing_keys:
            raise KeyError(
                f"Stored headers are missing required keys: {missing_keys}"
            )

        auth_params = auth_params or {}
        auth_context = {
            key: auth_params[key]
            for key in self._AUTH_CONTEXT_KEYS
            if key in auth_params
        }
        auth_context.update(
            {
                key: headers[key]
                for key in self._AUTH_CONTEXT_KEYS
                if key in headers
            }
        )
        missing_context_keys = [
            key for key in self._AUTH_CONTEXT_KEYS
            if key not in auth_context
        ]
        if missing_context_keys:
            raise KeyError(
                "Stored auth context is missing required keys: "
                f"{missing_context_keys}"
            )

        self._headers = {
            key: value
            for key, value in headers.items()
            if key not in self._AUTH_CONTEXT_KEYS
        }
        self._auth_context = auth_context
        if reset_session:
            self.reset_session()

        return {**self._headers, **self._auth_context}

    def log(self, *args: Any) -> None:
        """CCXT-style verbose logger hook."""
        print(*args)

    @staticmethod
    def _normalize_log_key(key: Any) -> str:
        """Normalise a header/field name for case-insensitive matching.

        Args:
            key: Raw key to normalise.

        Returns:
            The key lower-cased and trimmed with ``-`` replaced by ``_``.
        """
        return str(key).strip().lower().replace("-", "_")

    def _build_sensitive_log_keys(
        self,
        description: Mapping[str, Any],
    ) -> set[str]:
        """Build the set of log keys whose values must be redacted.

        Args:
            description: Merged broker description, read for ``sensitiveLogKeys``.

        Returns:
            Normalised sensitive keys, seeded with the library defaults when
            ``sensitiveLogKeysIncludeDefault`` is set.
        """
        configured_keys = description.get("sensitiveLogKeys", ())
        if isinstance(configured_keys, str):
            configured_keys = (configured_keys,)

        keys = set()
        if self.sensitiveLogKeysIncludeDefault:
            keys.update(
                self._normalize_log_key(key)
                for key in _DEFAULT_SENSITIVE_LOG_KEYS
            )

        keys.update(self._normalize_log_key(key) for key in configured_keys)
        return keys

    def _is_sensitive_log_key(self, key: Any) -> bool:
        """Return whether a key's value should be redacted from logs.

        Args:
            key: Header or payload field name to test.

        Returns:
            ``True`` if the normalised key is in ``self.sensitiveLogKeys``.
        """
        normalized = self._normalize_log_key(key)
        return normalized in self.sensitiveLogKeys

    def _redact_url(self, url: str) -> str:
        """Redact sensitive query-string values in a URL for logging.

        Returns ``url`` unchanged when ``logSensitive`` is set or it has no
        query string; otherwise sensitive query parameters are replaced with a
        redaction placeholder. Any parsing error falls back to the raw URL.

        Args:
            url: Request URL to sanitise.

        Returns:
            The URL with sensitive query values redacted.
        """
        if self.logSensitive:
            return url

        try:
            parts = urlsplit(url)
            if not parts.query:
                return url

            query = [
                (key, _REDACTED if self._is_sensitive_log_key(key) else value)
                for key, value in parse_qsl(parts.query, keep_blank_values=True)
            ]
            return urlunsplit(
                (parts.scheme, parts.netloc, parts.path,
                 urlencode(query), parts.fragment)
            )
        except Exception:
            return url

    def _redact_log_value(self, value: Any) -> Any:
        """Recursively redact sensitive values in a log payload.

        Walks mappings, lists and tuples (and JSON-encoded strings), replacing
        values under sensitive keys with a redaction placeholder. Returns the
        value unchanged when ``logSensitive`` is set.

        Args:
            value: Header set, body, or params to sanitise.

        Returns:
            A redacted copy of ``value`` (JSON re-serialised for JSON strings).
        """
        if self.logSensitive:
            return value

        if isinstance(value, Mapping):
            return {
                key: _REDACTED if self._is_sensitive_log_key(key)
                else self._redact_log_value(item)
                for key, item in value.items()
            }

        if isinstance(value, list):
            return [self._redact_log_value(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._redact_log_value(item) for item in value)

        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8", errors="replace")

        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith(("{", "[")):
                try:
                    parsed = loads(stripped)
                except Exception:
                    return value
                return dumps(self._redact_log_value(parsed), default=str)

        return value

    def _format_log_value(self, value: Any) -> Any:
        """Redact and length-truncate a value for logging.

        Applies ``_redact_log_value`` and, when ``maxLogBodyLength`` is set,
        truncates the rendered value beyond that length with a suffix noting
        how many characters were dropped.

        Args:
            value: Value to prepare for logging.

        Returns:
            The redacted value, possibly truncated to ``maxLogBodyLength``.
        """
        value = self._redact_log_value(value)
        max_length = self.maxLogBodyLength
        if not max_length:
            return value
        try:
            max_length = int(max_length)
        except (TypeError, ValueError):
            return value

        rendered = value if isinstance(value, str) else repr(value)
        if len(rendered) <= max_length:
            return value
        return f"{rendered[:max_length]}... (truncated {len(rendered) - max_length} chars)"

    def on_rest_response(
        self,
        code: int,
        reason: str,
        url: str,
        method: str,
        response_headers: Mapping[Any, Any],
        response_body: str,
        request_headers: Mapping[Any, Any],
        request_body: Any,
    ) -> str:
        """Hook for post-processing a raw REST response.

        The default implementation returns the stripped response body;
        subclasses may override it to decrypt or unwrap broker responses.

        Args:
            code: HTTP status code.
            reason: HTTP reason phrase.
            url: Final response URL.
            method: HTTP method of the request.
            response_headers: Response headers.
            response_body: Raw response body text.
            request_headers: Headers that were sent.
            request_body: Body that was sent.

        Returns:
            The processed response body text.
        """
        return response_body.strip()

    @staticmethod
    def on_json_response(response: Response | str) -> Any:
        """Decode a response (or string) body into a JSON value.

        Args:
            response: A ``requests`` ``Response`` or a raw body string.

        Returns:
            The decoded JSON value (dict or list).
        """
        if isinstance(response, Response):
            response_body = response.text.strip()
        else:
            response_body = str(response).strip()
        return loads(response_body)

    def parse_json(self, response_body: str) -> Any:
        """Decode a JSON body, returning ``None`` on failure.

        Args:
            response_body: Raw response body text.

        Returns:
            The decoded JSON value, or ``None`` if it cannot be parsed.
        """
        try:
            return self.on_json_response(response_body)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _stringify_error_payload(payload: Any) -> str:
        """Render an error payload as a string for messages.

        Args:
            payload: Error payload (str, dict, list, or ``None``).

        Returns:
            ``payload`` as a string: empty for ``None``, JSON for structured
            payloads, and ``str(payload)`` as a last resort.
        """
        if payload is None:
            return ""
        if isinstance(payload, str):
            return payload.strip()
        try:
            return dumps(payload, default=str)
        except (TypeError, ValueError):
            return str(payload)

    @classmethod
    def _find_error_field(cls, payload: Any, keys: tuple[str, ...]) -> Any:
        """Recursively search a payload for the first useful error field.

        Matches ``keys`` case-insensitively against dict keys, descending into
        nested dicts and lists, and returns the first non-empty value found.

        Args:
            payload: Decoded response payload to search.
            keys: Candidate field names to look for, in priority order.

        Returns:
            The first non-empty matching value, or ``None`` if none is found.
        """
        if isinstance(payload, dict):
            key_map = {str(key).lower(): key for key in payload}
            for key in keys:
                actual_key = key_map.get(key.lower())
                if actual_key is None:
                    continue
                value = payload.get(actual_key)
                if value not in (None, ""):
                    return value

            for value in payload.values():
                found = cls._find_error_field(value, keys)
                if found not in (None, ""):
                    return found

        if isinstance(payload, list):
            for item in payload:
                found = cls._find_error_field(item, keys)
                if found not in (None, ""):
                    return found

        return None

    def _response_error_payload(self, response: Response | None) -> Any:
        """Extract the most informative payload from an error response.

        Args:
            response: The offending response, or ``None``.

        Returns:
            The decoded JSON body when the body is JSON, otherwise the raw body
            string, or ``None`` when there is no response or body.
        """
        if response is None:
            return None

        body = (response.text or "").strip()
        if not body:
            return None

        if body.startswith(("{", "[")):
            try:
                return loads(body)
            except (TypeError, ValueError):
                pass

        return body

    def _extract_error_code(self, payload: Any) -> str | None:
        """Extract a broker error code from a payload.

        Uses the subclass's ``ERROR_CODE_KEYS`` to locate the code.

        Args:
            payload: Decoded response payload.

        Returns:
            The error code as a trimmed string, or ``None`` if absent.
        """
        error_code_keys = getattr(self, "ERROR_CODE_KEYS", ())
        if not error_code_keys:
            return None

        error_code = self._find_error_field(payload, tuple(error_code_keys))
        if error_code in (None, ""):
            return None
        return str(error_code).strip()

    def _extract_error_message(self, payload: Any) -> str | None:
        """Extract a broker error message from a payload.

        Uses the subclass's ``ERROR_MESSAGE_KEYS`` to locate the message.

        Args:
            payload: Decoded response payload.

        Returns:
            The error message as a trimmed string, or ``None`` if absent.
        """
        error_message_keys = getattr(self, "ERROR_MESSAGE_KEYS", ())
        if not error_message_keys:
            return None

        error_message = self._find_error_field(
            payload,
            tuple(error_message_keys),
        )
        if error_message in (None, ""):
            return None
        return str(error_message).strip()

    def _http_error_context(
        self,
        response: Response | None,
        payload: Any = None,
    ) -> dict[str, Any]:
        """Assemble a context dict describing a failed HTTP request.

        Args:
            response: The offending response, or ``None`` when the failure has
                no response (the last request's metadata is used instead).
            payload: Pre-decoded error payload; decoded from ``response`` when
                not supplied.

        Returns:
            A dict with ``method``, ``url``, ``status_code``, ``reason``,
            ``payload``, ``error_code``, ``error_message`` and ``response``.
        """
        if response is None:
            payload = payload if payload is not None else None
            return {
                "method": self.last_request_method,
                "url": self.last_request_url,
                "status_code": None,
                "reason": None,
                "payload": payload,
                "error_code": self._extract_error_code(payload),
                "error_message": self._extract_error_message(payload),
                "response": None,
            }

        payload = (
            self._response_error_payload(response)
            if payload is None
            else payload
        )
        request = getattr(response, "request", None)
        return {
            "method": (
                getattr(request, "method", None)
                or self.last_request_method
            ),
            "url": response.url or self.last_request_url,
            "status_code": response.status_code,
            "reason": response.reason,
            "payload": payload,
            "error_code": self._extract_error_code(payload),
            "error_message": self._extract_error_message(payload),
            "response": response,
        }

    def _format_http_error_message(self, context: dict[str, Any]) -> str:
        """Build a human-readable message from an HTTP error context.

        Args:
            context: Error context produced by ``_http_error_context``.

        Returns:
            A single-line message combining the broker id, status, method,
            URL and the most specific error detail available.
        """
        status_code = context.get("status_code")
        method = context.get("method")
        url = context.get("url")
        reason = context.get("reason")
        error_code = context.get("error_code")
        error_message = context.get("error_message")
        payload = context.get("payload")

        parts = [self.id]
        if status_code is not None:
            parts.append(f"HTTP {status_code}")
        if method:
            parts.append(str(method))
        if url:
            parts.append(str(url))

        detail = error_message or self._stringify_error_payload(payload) or reason
        if error_code and detail and str(error_code) not in str(detail):
            parts.append(f"- {error_code}: {detail}")
        elif error_code:
            parts.append(f"- {error_code}")
        elif detail:
            parts.append(f"- {detail}")

        return " ".join(str(part) for part in parts if part)

    @staticmethod
    def _http_error_class(status_code: int | None) -> type[BrokerError]:
        """Map an HTTP status code to a Fenix error class.

        Args:
            status_code: HTTP status code, or ``None``.

        Returns:
            The most specific ``BrokerError`` subclass for the status code
            (e.g. 401 → ``AuthenticationError``, 429 →
            ``RateLimitExceededError``, 5xx → ``NetworkError``), defaulting to
            ``BrokerError``.
        """
        if status_code is None:
            return BrokerError
        if status_code in {400, 422}:
            return InputError
        if status_code == 401:
            return AuthenticationError
        if status_code == 403:
            return PermissionDeniedError
        if status_code == 408:
            return RequestTimeoutError
        if status_code == 429:
            return RateLimitExceededError
        if status_code == 404:
            return ResponseError
        if status_code >= 500:
            return NetworkError
        return BrokerError

    def _log_http_request(
        self,
        method: str,
        url: str,
        headers: Mapping[Any, Any],
        body: Any,
        params: Any,
    ) -> None:
        """Log an outgoing HTTP request, redacting sensitive values.

        No-op unless ``verbose`` is set or the logger is enabled for DEBUG.

        Args:
            method: HTTP method.
            url: Request URL.
            headers: Request headers.
            body: Request body.
            params: Query parameters.
        """
        logger = getattr(self, "logger", None) or logging.getLogger(__name__)
        if not self.verbose and not logger.isEnabledFor(logging.DEBUG):
            return

        log_url = self._redact_url(url)
        log_headers = self._format_log_value(headers)
        log_body = self._format_log_value(body)
        log_params = self._format_log_value(params)

        if self.verbose:
            self.log(
                "\nfetch Request:",
                self.id,
                method,
                log_url,
                "RequestHeaders:",
                log_headers,
                "RequestBody:",
                log_body,
                "RequestParams:",
                log_params,
            )

        logger.debug(
            "%s %s, Request: headers=%s body=%s params=%s",
            method,
            log_url,
            log_headers,
            log_body,
            log_params,
        )

    def _log_http_response(
        self,
        method: str,
        url: str,
        status_code: int,
        headers: Mapping[Any, Any],
        body: Any,
    ) -> None:
        """Log a completed HTTP response, redacting sensitive values.

        No-op unless ``verbose`` is set or the logger is enabled for DEBUG.

        Args:
            method: HTTP method of the request.
            url: Response URL.
            status_code: HTTP status code.
            headers: Response headers.
            body: Response body.
        """
        logger = getattr(self, "logger", None) or logging.getLogger(__name__)
        if not self.verbose and not logger.isEnabledFor(logging.DEBUG):
            return

        log_url = self._redact_url(url)
        log_headers = self._format_log_value(headers)
        log_body = self._format_log_value(body)

        if self.verbose:
            self.log(
                "\nfetch Response:",
                self.id,
                method,
                log_url,
                status_code,
                "ResponseHeaders:",
                log_headers,
                "ResponseBody:",
                log_body,
            )

        logger.debug(
            "%s %s, Response: %s headers=%s body=%s",
            method,
            log_url,
            status_code,
            log_headers,
            log_body,
        )

    def _record_paper_interaction(self, event: Mapping[str, Any]) -> None:
        """Store paper-mode request/response snapshots like ``fetch()`` does."""
        snapshot = deepcopy(dict(event))
        operation = snapshot.get("operation") or "paper"
        synthetic_url = f"paper://{self.id}/{operation}"
        request_body = snapshot.get("request")
        response_body = snapshot.get("response")

        self.last_paper_interaction = snapshot
        self.last_paper_request = request_body
        self.last_paper_response = response_body

        self.last_request_method = str(operation).upper()
        self.last_request_url = synthetic_url
        self.last_request_headers = {"paper": "true"}
        self.last_request_body = request_body
        self.last_request_params = None
        self.last_response_url = synthetic_url

        if self.enableLastHttpResponse:
            self.last_http_response = response_body
        if self.enableLastJsonResponse:
            self.last_json_response = response_body
        if self.enableLastResponseHeaders:
            self.last_response_headers = {}

    def throttle(self, endpoint_group: str) -> None:
        """
        Rate limiter using context manager for clean lock handling.
        Acquires all relevant bucket locks and holds them during sleep.
        """
        if not self.enableRateLimit:
            return

        relevant_bucket_names = [
            name for name in self._token_buckets
            if name.startswith(f"{endpoint_group}_")
        ]

        if not relevant_bucket_names:
            self.logger.debug(
                f"No rate limit bucket defined for group '{endpoint_group}'. Proceeding.")
            return

        # Use ExitStack to manage multiple locks as context managers
        with ExitStack() as stack:
            # Acquire all locks for this endpoint group
            for bucket_name in relevant_bucket_names:
                stack.enter_context(self._bucket_locks[bucket_name])

            # All locks are now held - calculate wait time
            max_wait_time = 0.0

            # Refill all buckets
            now = time.monotonic()
            for bucket_name in relevant_bucket_names:
                bucket = self._token_buckets[bucket_name]
                time_elapsed = now - bucket['last_refill_time']
                refilled_tokens = time_elapsed * bucket['refill_rate']
                bucket['tokens'] = min(
                    bucket['capacity'],
                    bucket['tokens'] + refilled_tokens
                )
                bucket['last_refill_time'] = now

            # Check if all buckets have enough tokens
            for bucket_name in relevant_bucket_names:
                bucket = self._token_buckets[bucket_name]
                cost = bucket.get('cost', 1.0)
                if bucket['tokens'] < cost:
                    required_tokens = cost - bucket['tokens']
                    wait_time = required_tokens / bucket['refill_rate']
                    max_wait_time = max(max_wait_time, wait_time)

            # If we need to wait, sleep WITH locks held
            if max_wait_time > 0:
                padded_wait_time = max_wait_time * self.rate_limit_padding
                self.logger.debug(
                    f"Rate limit hit on group '{endpoint_group}'. "
                    f"Waiting {padded_wait_time:.4f}s with locks held."
                )
                time.sleep(padded_wait_time)

                # After sleeping, refill tokens again before consuming
                now = time.monotonic()
                for bucket_name in relevant_bucket_names:
                    bucket = self._token_buckets[bucket_name]
                    time_elapsed = now - bucket['last_refill_time']
                    refilled_tokens = time_elapsed * bucket['refill_rate']
                    bucket['tokens'] = min(
                        bucket['capacity'],
                        bucket['tokens'] + refilled_tokens
                    )
                    bucket['last_refill_time'] = now

            # Consume tokens from all buckets
            for bucket_name in relevant_bucket_names:
                bucket = self._token_buckets[bucket_name]
                cost = bucket.get('cost', 1.0)
                bucket['tokens'] -= cost

        # ExitStack automatically releases all locks here (even if exception
        # occurs)

    def fetch(
        self,
        method: str,
        url: str,
        endpoint_group: str,
        headers: dict[Any, Any] | None = None,
        data: dict[Any, Any] | None = None,
        json: dict[Any, Any] | None = None,
        params: dict[Any, Any] | None = None,
        auth: tuple[str, str] | None = None,
        timeout: int = 10,
        verify: bool = True,
        allow_redirects: bool = True,
    ) -> Response:
        """
        A Wrapper for Python Requests module,
        sending requests over a session which persists the cookies over the entire session.

        Args:
            method (str): Request Method: 'GET', 'POST', 'PUT', 'DELETE', 'GET', etc.
            url (str): URL of the Request
            endpoint_group (str): Rate-limit bucket prefix used to throttle the request via ``throttle()``.
            headers (dict[Any, Any] | None, optional): Request Headers. Defaults to None.
            data (dict[Any, Any] | None, optional): Dictionary, list of tuples, bytes, or file-like object to send in the body of the Request. Defaults to None.
            json (dict[Any, Any] | None, optional): A JSON serializable Python object to send in the body of the Request. Defaults to None.
            params (dict[Any, Any] | None, optional): Dictionary, list of tuples or bytes to send in the query string for the Request. Defaults to None.
            auth (tuple[str, str] | None, optional): Auth tuple to enable Basic/Digest/Custom HTTP Auth. Defaults to None.
            timeout (int, optional): How many seconds to wait for the server to send data before giving up. Defaults to 10.
            verify (bool, optional): Whether to verify the server's TLS certificate. Defaults to True.
            allow_redirects (bool, optional): Whether to follow HTTP redirects. Defaults to True.

        Raises:
            RequestTimeoutError: If the Request Times Out
            NetworkError: If Network Unavailable.
            BrokerError: If Error on Behalf of the Broker or Some Error on behalf of the User sending the Request.

        Returns:
            Response: Response Object
        """
        self.throttle(endpoint_group)
        request_body = json if json is not None else data
        request_headers = {**(headers or {})}

        self.last_request_headers = request_headers
        self.last_request_body = request_body
        self.last_request_params = params
        self.last_request_url = url
        self.last_request_method = method

        try:
            self._log_http_request(
                method,
                url,
                request_headers,
                request_body,
                params,
            )

            response = self._session.request(
                method=method,
                url=url,
                headers=request_headers,
                data=data,
                json=json,
                params=params,
                auth=auth,
                timeout=timeout,
                verify=verify,
                allow_redirects=allow_redirects,
                proxies=self.proxies
            )

            http_response = self.on_rest_response(
                response.status_code,
                response.reason,
                response.url,
                method,
                response.headers,
                response.text,
                request_headers,
                request_body,
            )
            json_response = (
                self.parse_json(http_response)
                if self.enableLastJsonResponse
                else None
            )

            if self.enableLastHttpResponse:
                self.last_http_response = http_response
            if self.enableLastJsonResponse:
                self.last_json_response = json_response
            if self.enableLastResponseHeaders:
                self.last_response_headers = response.headers
            self.last_response_url = response.url

            self._log_http_response(
                method,
                response.url,
                response.status_code,
                response.headers,
                http_response,
            )

            response.raise_for_status()

            return response

        except Timeout as exc:
            details = " ".join([self.id, method, url])
            raise RequestTimeoutError(details) from exc

        except TooManyRedirects as exc:
            details = " ".join([self.id, method, url])
            raise BrokerError(details) from exc

        except HTTPError as exc:
            details = " ".join([self.id, method, url])
            self.handle_http_error(exc)
            raise BrokerError(details) from exc

        except (RequestsConnectionError, SSLError, ConnectionResetError) as exc:
            raise NetworkError(
                f"{self.id} {method} {url} - {str(exc)} - {exc.request.url}") from exc

        except RequestException as exc:
            raise BrokerError(
                f"{self.id} {method} {url} - {str(exc)}") from exc

    def handle_http_error(self, exc: HTTPError) -> NoReturn:
        """
        Default handler for HTTP errors. Child classes should override this
        for broker-specific error handling.
        """
        context = self._http_error_context(exc.response)
        error_cls = self._http_error_class(context.get("status_code"))
        raise error_cls(
            self._format_http_error_message(context),
            broker=self.id,
            error_code=context.get("error_code"),
            status_code=context.get("status_code"),
            payload=context.get("payload"),
            url=context.get("url"),
            method=context.get("method"),
            response=context.get("response"),
        ) from exc

    def _json_parser(self, response: Response) -> Any:
        """
        Get json object from a request Response.

        Args:
            response (Response): Response Object

        Returns:
            Any: Parsed JSON payload (dict or list — typed as Any, matching
            the convention used by requests/httpx for untyped JSON data).
        """
        try:
            parsed_response = self.on_json_response(response.text.strip())
            if self.enableLastJsonResponse:
                self.last_json_response = parsed_response
            if self.returnResponseHeaders and isinstance(parsed_response, dict):
                parsed_response = {
                    **parsed_response,
                    "responseHeaders": response.headers,
                }
            return parsed_response

        except Exception as exc:
            raise ResponseError(
                {
                    "Status": response.status_code,
                    "Error": response.text,
                    "URL": response.url,
                    "Reason": response.reason,
                }
            ) from exc

    @staticmethod
    def _eq_mapper(
        dictionary: dict,
        key: str,
    ) -> str:
        """
        A Simple Function to help the User if they input a wrong Symbol in the eq_tokens dictionary,
        also tells the User the possible Symbols for the Segment.

        Args:
            dictionary (dict): Dictionary
            key (str): Dictionary Key to Check Against, should be capital Letters.

        Raises:
            KeyError: If Key Does not exist in the Dictionary.

        Returns:
            str: The Value of the Key in the Dictionary.
        """
        key = key.upper()
        if key in dictionary:
            return dictionary[key]

        r = compile(r"[A-Z]*<str>[A-Z]*$".replace("<str>", key))
        possible_values = list(filter(r.findall, dictionary))

        raise KeyError(
            f"Invalid Symbol!: {key}, Possible Values: {possible_values}")

    @staticmethod
    def totp_creator(totp_base: str) -> str:
        """
        Get TOTP from the character string.

        Args:
            totp_base (str): String used to Generate TOTP.

        Returns:
            str: Six-Digit TOTP
        """
        while True:
            totp_obj = TOTP(totp_base)
            totp = totp_obj.now()

            if totp_obj.verify(totp):
                return totp


    @classmethod
    def cookie_getter(cls) -> None:
        """Fetch and cache NSE cookies for option-chain requests.

        Performs a warm-up GET against the NSE option-chain page and stores the
        returned cookies on ``cls.cookies`` for reuse by the expiry/option-chain
        downloads. Network errors are printed and swallowed.
        """
        try:
            headers = {
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "accept-language": "en-GB,en;q=0.9",
                "dnt": "1",
                "sec-ch-ua": '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "none",
                "sec-fetch-user": "?1",
                "upgrade-insecure-requests": "1",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            }

            temp_session = cls._create_session()
            response = temp_session.request(
                method="GET",
                url="https://www.nseindia.com/option-chain",
                headers=headers)
            cls.cookies = dict(response.cookies)
        except Exception as e:
            print(e)

    @classmethod
    def download_expiry_dates_nfo(
        cls,
        root: str,
    ) -> list[str]:
        """Download and cache NSE F&O expiry dates for an underlying.

        Fetches expiries from NSE (priming cookies first when needed), filters
        them via ``dates_filter`` and caches the result on
        ``cls.expiry_dates[root]``.

        Args:
            root: Underlying root symbol (e.g. ``Root.NF``).

        Returns:
            The filtered list of expiry-date strings.

        Raises:
            BrokerError: If the expiry dates cannot be fetched.
        """
        temp_session = req_session()

        try:
            headers = {
                "accept": "*/*",
                "accept-language": "en-GB,en-US;q=0.9,en;q=0.8,hi;q=0.7",
                "dnt": "1",
                "referer": "https://www.nseindia.com/option-chain",
                "sec-ch-ua": '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            }

            params = {
                "symbol": f"{root}",
            }

            if not cls.cookies:
                cls.cookie_getter()

            response = temp_session.request(
                method="GET",
                url=cls.NFO_URL,
                params=params,
                cookies=cls.cookies,
                headers=headers,
                timeout=10,
            )
            data = response.json()
            expiry_dates = data["records"]["expiryDates"]
            cls.expiry_dates[root] = cls.dates_filter(expiry_dates)
            return cls.expiry_dates[root]

        except Exception as e:
            raise BrokerError(
                f"Cannot Fetch Expiry Date from NSE for: {root}, Error:{e}")

    @classmethod
    def download_expiry_dates_bfo(
        cls,
        root: str,
    ) -> list[str]:
        """Download and cache BSE F&O expiry dates for an underlying.

        Resolves the BSE scrip code for ``root`` (SENSEX/BANKEX), fetches its
        expiries, filters them via ``dates_filter`` and caches the result on
        ``cls.expiry_dates[root]``.

        Args:
            root: Underlying root symbol (``Root.SENSEX`` or ``Root.BANKEX``).

        Returns:
            The filtered list of expiry-date strings.

        Raises:
            BrokerError: If the expiry dates cannot be fetched.
        """
        if root == Root.SENSEX:
            scrip_cd = 1
        elif root == Root.BANKEX:
            scrip_cd = 12
        else:
            scrip_cd = 1

        temp_session = req_session()

        try:
            headers = {
                "accept": "application/json, text/plain, */*",
                "accept-language": "en-GB,en-US;q=0.9,en;q=0.8,hi;q=0.7",
                "dnt": "1",
                "if-modified-since": "Sun, 24 Mar 2024 11:21:31 GMT",
                "origin": "https://www.bseindia.com",
                "referer": "https://www.bseindia.com/",
                "sec-ch-ua": '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-site",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            }

            params = {
                "ProductType": "IO",
                "scrip_cd": scrip_cd,
            }

            response = temp_session.request(
                method="GET",
                url=cls.BFO_URL,
                params=params,
                headers=headers,
                timeout=10,
            )
            data = response.json()

            expiry_dates = data["Table1"]
            expiry_dates = [i["ExpiryDate"] for i in expiry_dates]
            cls.expiry_dates[root] = cls.dates_filter(expiry_dates)
            return cls.expiry_dates[root]

        except Exception as e:
            raise BrokerError(
                f"Cannot Fetch Expiry Date from NSE for: {root}, Error:{e}")
