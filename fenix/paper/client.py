"""Paper-trading execution client.

Held by each broker as ``self._paper`` when ``paper_mode=True``. The
broker's order-entry and read methods route here instead of issuing HTTP
calls. Orders rest in :class:`MatchingEngine` instances (one per token);
ticks fed via :meth:`on_tick` drive fills, position updates, and PnL.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from copy import deepcopy
from datetime import datetime
from typing import Any, Callable, TypeVar

from fenix.base.constants import (
    Order,
    OrderType,
    Position,
    Side,
    Status,
    Validity,
    Variety,
)
from fenix.base.errors import InputError, InvalidOrderError, OrderNotFoundError

from fenix.paper.matching_engine import MatchingEngine
from fenix.paper.state import PaperState


_T = TypeVar("_T")


class PaperExecutionClient:
    """Drop-in replacement for a broker's order/read methods in paper mode."""

    def __init__(
        self,
        broker_id: str = "paper",
        client_id: str = "PAPER001",
        starting_margin: float = 1_000_000.0,
        reject_invalid_stops: bool = True,
        logger: logging.Logger | None = None,
        verbose: bool = False,
        log_hook: Callable[..., None] | None = None,
        format_log_value: Callable[[Any], Any] | None = None,
        interaction_hook: Callable[[dict[str, Any]], None] | None = None,
        max_interactions: int = 100,
    ) -> None:
        """Initialize the paper client and its backing state.

        Args:
            broker_id: Identifier of the owning broker, echoed in logs and
                synthetic records.
            client_id: Client identifier reported by the paper profile.
            starting_margin: Opening available margin for the session.
            reject_invalid_stops: When ``True``, stop orders priced through
                the market on submission are rejected (see
                :meth:`_validate_stop_against_ltp`).
            logger: Logger to use; defaults to this module's logger.
            verbose: When ``True``, request/response activity is also written
                through ``log_hook`` in addition to debug logging.
            log_hook: Callable used for verbose output; defaults to ``print``.
            format_log_value: Callable applied to values before logging, e.g.
                to redact secrets; defaults to an identity function.
            interaction_hook: Optional callback invoked with a snapshot of
                every recorded interaction.
            max_interactions: Maximum number of interactions retained in the
                rolling history buffer.
        """
        self.broker_id = broker_id
        self.reject_invalid_stops = reject_invalid_stops
        self.logger = logger or logging.getLogger(__name__)
        self.verbose = bool(verbose)
        self.log_hook = log_hook or print
        self._format_log_value = format_log_value or (lambda value: value)
        self._interaction_hook = interaction_hook
        self.last_paper_request: dict[str, Any] | None = None
        self.last_paper_response: Any = None
        self.last_paper_interaction: dict[str, Any] | None = None
        self.interactions: deque[dict[str, Any]] = deque(
            maxlen=self._coerce_history_size(max_interactions)
        )
        self.state = PaperState(
            broker_id=broker_id,
            client_id=client_id,
            starting_margin=starting_margin,
        )
        self.engines: dict[int, MatchingEngine] = {}

    @staticmethod
    def _coerce_history_size(value: int) -> int:
        """Coerce a configured history size to a safe non-negative int.

        Args:
            value: The configured ``max_interactions`` value, possibly of an
                unexpected type.

        Returns:
            ``value`` as a non-negative int, or ``100`` if it cannot be
            interpreted as an integer.
        """
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return 100

    @staticmethod
    def _snapshot(value: _T) -> _T | str:
        """Return a deep copy of ``value`` safe to store and log.

        Decoupling stored snapshots from live objects keeps the interaction
        history immutable even as the underlying orders/positions change.

        Args:
            value: The object to snapshot.

        Returns:
            A deep copy of ``value``, or its ``repr`` if it cannot be copied.
        """
        try:
            return deepcopy(value)
        except Exception:
            return repr(value)

    def _format_for_log(self, value: Any) -> Any:
        """Apply the configured log formatter, falling back to the raw value.

        Args:
            value: The value about to be logged.

        Returns:
            The formatter's output, or the original ``value`` if formatting
            raises.
        """
        try:
            return self._format_log_value(value)
        except Exception:
            return value

    def _should_log(self) -> bool:
        """Report whether request/response activity should be logged.

        Returns:
            ``True`` if verbose mode is on or the logger is enabled for
            ``DEBUG``.
        """
        return self.verbose or self.logger.isEnabledFor(logging.DEBUG)

    def _log_paper_request(self, operation: str, request: Any) -> None:
        """Log an outgoing paper request, if logging is enabled.

        Args:
            operation: Name of the operation being performed (e.g.
                ``"place_order"``).
            request: The request payload to log.
        """
        if not self._should_log():
            return

        log_request = self._format_for_log(request)
        if self.verbose:
            self.log_hook(
                "\npaper Request:",
                self.broker_id,
                operation,
                "RequestBody:",
                log_request,
            )
        self.logger.debug(
            "paper %s Request: broker=%s body=%s",
            operation,
            self.broker_id,
            log_request,
        )

    def _log_paper_response(
        self,
        operation: str,
        status: str,
        response: Any,
        duration_ms: float,
    ) -> None:
        """Log a completed paper response, if logging is enabled.

        Args:
            operation: Name of the operation that produced the response.
            status: Outcome marker, ``"OK"`` or ``"ERROR"``.
            response: The response payload (or error envelope) to log.
            duration_ms: Wall-clock duration of the operation in milliseconds.
        """
        if not self._should_log():
            return

        log_response = self._format_for_log(response)
        if self.verbose:
            self.log_hook(
                "\npaper Response:",
                self.broker_id,
                operation,
                status,
                f"{duration_ms:.3f}ms",
                "ResponseBody:",
                log_response,
            )
        self.logger.debug(
            "paper %s Response: broker=%s status=%s duration_ms=%.3f body=%s",
            operation,
            self.broker_id,
            status,
            duration_ms,
            log_response,
        )

    def _record_interaction(
        self,
        operation: str,
        request: Any,
        response: Any,
        status: str,
        duration_ms: float,
    ) -> None:
        """Record one interaction into the rolling history and fire the hook.

        Updates the ``last_paper_*`` attributes, appends a snapshot to the
        bounded interaction buffer, and invokes ``interaction_hook`` if one
        was supplied. A failing hook is logged but never propagated.

        Args:
            operation: Name of the operation performed.
            request: Snapshot of the request payload.
            response: Snapshot of the response payload (or error envelope).
            status: Outcome marker, ``"OK"`` or ``"ERROR"``.
            duration_ms: Wall-clock duration of the operation in milliseconds.
        """
        event = {
            "mode": "paper",
            "broker": self.broker_id,
            "operation": operation,
            "status": status,
            "duration_ms": round(duration_ms, 3),
            "timestamp": datetime.now().replace(microsecond=0).isoformat(),
            "request": self._snapshot(request),
            "response": self._snapshot(response),
        }
        self.last_paper_request = event["request"]
        self.last_paper_response = event["response"]
        self.last_paper_interaction = self._snapshot(event)
        self.interactions.append(self._snapshot(event))

        if self._interaction_hook is None:
            return
        try:
            self._interaction_hook(self._snapshot(event))
        except Exception:
            self.logger.exception("paper interaction hook failed")

    def _execute(
        self,
        operation: str,
        request: dict[str, Any],
        handler: Callable[[], _T],
    ) -> _T:
        """Run an operation with uniform logging, timing and recording.

        Every public method funnels through here: the request is snapshotted
        and logged, ``handler`` runs under a timer, and the result (or the
        raised exception) is recorded and logged before being returned or
        re-raised.

        Args:
            operation: Name of the operation, used in logs and history.
            request: The request payload describing the call.
            handler: Zero-argument callable that performs the actual work and
                returns the response.

        Returns:
            Whatever ``handler`` returns.

        Raises:
            Exception: Re-raises any exception raised by ``handler`` after
                recording it as an ``ERROR`` interaction.
        """
        request_snapshot = self._snapshot(request)
        self.last_paper_request = request_snapshot
        self._log_paper_request(operation, request_snapshot)
        started = time.perf_counter()

        try:
            response = handler()
        except Exception as exc:
            duration_ms = (time.perf_counter() - started) * 1000
            error_response = {
                "error": {
                    "type": exc.__class__.__name__,
                    "message": str(exc),
                }
            }
            self._record_interaction(
                operation,
                request_snapshot,
                error_response,
                "ERROR",
                duration_ms,
            )
            self._log_paper_response(
                operation,
                "ERROR",
                error_response,
                duration_ms,
            )
            raise

        duration_ms = (time.perf_counter() - started) * 1000
        response_snapshot = self._snapshot(response)
        self._record_interaction(
            operation,
            request_snapshot,
            response_snapshot,
            "OK",
            duration_ms,
        )
        self._log_paper_response(
            operation,
            "OK",
            response_snapshot,
            duration_ms,
        )
        return response

    # ── Tick feed ─────────────────────────────────────────────────────────

    def on_tick(
        self,
        token: int,
        ltp: float | None = None,
        bid: float | None = None,
        ask: float | None = None,
    ) -> list[dict[str, Any]]:
        """Push a tick. Returns orders newly filled on this tick.

        Routes the tick to the instrument's matching engine, refreshes the
        position LTP, and applies any resulting fills to the positions book.

        Args:
            token: Instrument token the tick belongs to.
            ltp: Last traded price for this tick.
            bid: Best bid price for this tick (optional).
            ask: Best ask price for this tick (optional).

        Returns:
            Copies of the order records that filled as a result of this tick.
        """
        request = {
            "token": int(token),
            "ltp": ltp,
            "bid": bid,
            "ask": ask,
        }
        return self._execute(
            "on_tick",
            request,
            lambda: self._on_tick(token=token, ltp=ltp, bid=bid, ask=ask),
        )

    def _on_tick(
        self,
        token: int,
        ltp: float | None = None,
        bid: float | None = None,
        ask: float | None = None,
    ) -> list[dict[str, Any]]:
        """Drive matching for one tick and update positions from the fills.

        Args:
            token: Instrument token the tick belongs to.
            ltp: Last traded price for this tick.
            bid: Best bid price for this tick (optional).
            ask: Best ask price for this tick (optional).

        Returns:
            Copies of the order records that filled on this tick.
        """
        engine = self._get_engine(int(token))
        filled = engine.on_tick(ltp=ltp, bid=bid, ask=ask)
        if ltp is not None:
            self.state.update_ltp(int(token), float(ltp))
        for order in filled:
            self.state.update_position_on_fill(order)
        return [deepcopy(order) for order in filled]

    # ── Order entry ───────────────────────────────────────────────────────

    def place_order(
        self,
        token_dict: dict[str, Any],
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
        trailing_sl: float = 0.0,
        extra_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Place a simulated order and return its id.

        The order type is inferred from ``price`` and ``trigger`` (market,
        limit, SL, or SL-M). Market orders fill against the latest tick if one
        exists, otherwise they rest until the next tick; limit and stop orders
        rest in the matching engine until their conditions are met.

        Args:
            token_dict: Instrument metadata; must contain ``"Token"`` and
                typically ``"Symbol"`` and ``"Exchange"``.
            quantity: Order quantity; must be greater than zero.
            side: Order side, ``Side.BUY`` or ``Side.SELL``.
            product: Product code (informational in paper mode).
            validity: Order validity (informational in paper mode).
            variety: Order variety (informational in paper mode).
            unique_id: Caller-supplied order tag, stored as the user order id.
            price: Limit price; zero implies a market/SL-M order.
            trigger: Stop trigger price; zero implies a non-stop order.
            target: Bracket-order target price (stored, not simulated).
            stoploss: Bracket-order stop-loss price (stored, not simulated).
            trailing_sl: Bracket-order trailing stop-loss (stored, not
                simulated).
            extra_params: Optional escape hatch; ``{"force_status": ...}`` can
                force an immediate ``Status.FILLED`` or ``Status.REJECTED``.

        Returns:
            A dict with the new order id under ``Order.ID``.

        Raises:
            InputError: If the quantity or a price field is invalid.
            InvalidOrderError: If a stop is priced through the market and
                stop rejection is enabled.
        """
        request = {
            "token_dict": token_dict,
            "quantity": quantity,
            "side": side,
            "product": product,
            "validity": validity,
            "variety": variety,
            "unique_id": unique_id,
            "price": price,
            "trigger": trigger,
            "target": target,
            "stoploss": stoploss,
            "trailing_sl": trailing_sl,
            "extra_params": extra_params,
        }
        return self._execute(
            "place_order",
            request,
            lambda: self._place_order(
                token_dict=token_dict,
                quantity=quantity,
                side=side,
                product=product,
                validity=validity,
                variety=variety,
                unique_id=unique_id,
                price=price,
                trigger=trigger,
                target=target,
                stoploss=stoploss,
                trailing_sl=trailing_sl,
                extra_params=extra_params,
            ),
        )

    def _place_order(
        self,
        token_dict: dict[str, Any],
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
        trailing_sl: float = 0.0,
        extra_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Validate, build, and register a simulated order.

        Implements the order-placement logic behind :meth:`place_order`:
        inputs are validated, the order type is resolved, stops are checked
        against the market, and the order is either filled immediately or
        registered to rest in its matching engine.

        Args:
            token_dict: Instrument metadata; must contain ``"Token"``.
            quantity: Order quantity; must be greater than zero.
            side: Order side, ``Side.BUY`` or ``Side.SELL``.
            product: Product code (informational in paper mode).
            validity: Order validity (informational in paper mode).
            variety: Order variety (informational in paper mode).
            unique_id: Caller-supplied order tag.
            price: Limit price; zero implies a market/SL-M order.
            trigger: Stop trigger price; zero implies a non-stop order.
            target: Bracket-order target price (stored, not simulated).
            stoploss: Bracket-order stop-loss price (stored, not simulated).
            trailing_sl: Bracket-order trailing stop-loss (stored, not
                simulated).
            extra_params: Optional ``{"force_status": ...}`` escape hatch.

        Returns:
            A dict with the new order id under ``Order.ID``.

        Raises:
            InputError: If the quantity, side, or a price field is invalid.
            InvalidOrderError: If a stop is priced through the market and
                stop rejection is enabled.
        """
        self._validate_order_inputs(
            quantity=quantity,
            price=price,
            trigger=trigger,
            target=target,
            stoploss=stoploss,
            trailing_sl=trailing_sl,
        )
        self._validate_side(side)

        order_type = self._resolve_order_type(price, trigger)
        token = int(token_dict["Token"])
        engine = self._get_engine(token)

        self._validate_stop_against_ltp(order_type, side, price, trigger, engine)

        order = self._build_order(
            token_dict=token_dict,
            quantity=quantity,
            side=side,
            product=product,
            validity=validity,
            variety=variety,
            unique_id=unique_id,
            price=price,
            trigger=trigger,
            target=target,
            stoploss=stoploss,
            trailing_sl=trailing_sl,
            order_type=order_type,
        )

        # Optional escape hatch: extra_params={"force_status": Status.FILLED}
        # mirrors the old paper.py behaviour for tests that want to bypass
        # tick-driven matching entirely.
        forced = (extra_params or {}).get("force_status")
        if forced == Status.FILLED:
            self._force_fill(order, engine, fallback_price=price or trigger)
            self.state.add_order(order)
            self.state.update_position_on_fill(order)
            return {Order.ID: order[Order.ID]}
        if forced == Status.REJECTED:
            order[Order.STATUS] = Status.REJECTED
            order[Order.REJECT_REASON] = (extra_params or {}).get(
                "reject_reason", "Forced reject"
            )
            self.state.add_order(order)
            return {Order.ID: order[Order.ID]}

        if order_type == OrderType.MARKET:
            ltp = engine.tick.ltp
            if ltp is not None:
                self._force_fill(order, engine, fallback_price=ltp)
                self.state.add_order(order)
                self.state.update_position_on_fill(order)
                return {Order.ID: order[Order.ID]}
            # No tick yet — leave pending; on_tick() will fill it.
            order[Order.STATUS] = Status.PENDING
            engine.register(order)
        elif order_type == OrderType.LIMIT:
            order[Order.STATUS] = Status.OPEN
            engine.register(order)
        else:  # SL or SLM — wait for trigger
            order[Order.STATUS] = Status.PENDING
            engine.register(order)

        self.state.add_order(order)
        return {Order.ID: order[Order.ID]}

    def modify_order(
        self,
        order_id: str,
        price: float | None = None,
        trigger: float | None = None,
        quantity: int | None = None,
        order_type: str | None = None,
        validity: str | None = None,
        raw_order_json: dict[str, Any] | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> None:
        """Modify a resting order in place.

        Only orders still pending or open can be modified. Supplied fields
        overwrite the existing ones; omitted (``None``) fields are left
        unchanged. The order's working status is re-derived afterwards.

        Args:
            order_id: Id of the order to modify.
            price: New limit price, or ``None`` to leave unchanged.
            trigger: New stop trigger price, or ``None`` to leave unchanged.
            quantity: New quantity, or ``None`` to leave unchanged.
            order_type: New order type, or ``None`` to leave unchanged.
            validity: New validity, or ``None`` to leave unchanged.
            raw_order_json: Optional raw payload whose ``Order.ID`` takes
                precedence over ``order_id`` when locating the order.
            extra_params: Unused; accepted for signature parity with brokers.

        Raises:
            OrderNotFoundError: If no matching order exists.
            InvalidOrderError: If the order is not in a modifiable status.
            InputError: If a supplied field has an invalid value.
        """
        request = {
            "order_id": order_id,
            "price": price,
            "trigger": trigger,
            "quantity": quantity,
            "order_type": order_type,
            "validity": validity,
            "raw_order_json": raw_order_json,
            "extra_params": extra_params,
        }
        return self._execute(
            "modify_order",
            request,
            lambda: self._modify_order(
                order_id=order_id,
                price=price,
                trigger=trigger,
                quantity=quantity,
                order_type=order_type,
                validity=validity,
                raw_order_json=raw_order_json,
                extra_params=extra_params,
            ),
        )

    def _modify_order(
        self,
        order_id: str,
        price: float | None = None,
        trigger: float | None = None,
        quantity: int | None = None,
        order_type: str | None = None,
        validity: str | None = None,
        raw_order_json: dict[str, Any] | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> None:
        """Apply an in-place modification to a resting order.

        Implements the logic behind :meth:`modify_order`: locates the order,
        validates each supplied field, mutates the record, re-checks any stop
        against the market, and refreshes its working status and timestamp.

        Args:
            order_id: Id of the order to modify.
            price: New limit price, or ``None`` to leave unchanged.
            trigger: New stop trigger price, or ``None`` to leave unchanged.
            quantity: New quantity, or ``None`` to leave unchanged.
            order_type: New order type, or ``None`` to leave unchanged.
            validity: New validity, or ``None`` to leave unchanged.
            raw_order_json: Optional raw payload whose ``Order.ID`` takes
                precedence over ``order_id`` when locating the order.
            extra_params: Unused; accepted for signature parity with brokers.

        Raises:
            OrderNotFoundError: If no matching order exists.
            InvalidOrderError: If the order is not in a modifiable status.
            InputError: If a supplied field has an invalid value.
        """
        target_id = (raw_order_json or {}).get(Order.ID) or str(order_id)
        order = self.state.find_order(target_id)
        if order is None:
            raise OrderNotFoundError(f"Paper: order {target_id!r} not found.")

        if order[Order.STATUS] not in (Status.PENDING, Status.OPEN):
            raise InvalidOrderError(
                f"Paper: cannot modify order {target_id!r} in status "
                f"{order[Order.STATUS]!r}."
            )

        if quantity is not None:
            if int(quantity) <= 0:
                raise InputError("Paper: order quantity must be greater than 0.")
            order[Order.QUANTITY] = int(quantity)
            order[Order.REMAINING_QTY] = int(quantity)
        if validity is not None:
            order[Order.VALIDITY] = validity
        if order_type is not None:
            self._validate_order_type(order_type)
            order[Order.TYPE] = order_type
        if price is not None:
            if float(price) < 0:
                raise InputError("Paper: order price must be non-negative.")
            order[Order.PRICE] = float(price)
        if trigger is not None:
            if float(trigger) < 0:
                raise InputError("Paper: order trigger must be non-negative.")
            order[Order.TRIGGER_PRICE] = float(trigger)

        engine = self._get_engine(int(order[Order.TOKEN]))
        self._validate_stop_against_ltp(
            order_type=order[Order.TYPE],
            side=order[Order.SIDE],
            price=float(order[Order.PRICE]),
            trigger=float(order[Order.TRIGGER_PRICE]),
            engine=engine,
        )
        order[Order.STATUS] = (
            Status.OPEN if order[Order.TYPE] == OrderType.LIMIT else Status.PENDING
        )
        order[Order.TIMESTAMP] = datetime.now().replace(microsecond=0)
        return None

    def cancel_order(
        self,
        order_id: str,
        extra_params: dict[str, Any] | None = None,
    ) -> None:
        """Cancel a resting order.

        Args:
            order_id: Id of the order to cancel.
            extra_params: Unused; accepted for signature parity with brokers.

        Raises:
            OrderNotFoundError: If no matching order exists.
        """
        request = {"order_id": order_id, "extra_params": extra_params}
        return self._execute(
            "cancel_order",
            request,
            lambda: self._cancel_order(order_id=order_id, extra_params=extra_params),
        )

    def _cancel_order(
        self,
        order_id: str,
        extra_params: dict[str, Any] | None = None,
    ) -> None:
        """Deregister a resting order and mark its remaining quantity cancelled.

        Orders that are no longer pending or open are left untouched (the call
        is a no-op for already-terminal orders).

        Args:
            order_id: Id of the order to cancel.
            extra_params: Unused; accepted for signature parity with brokers.

        Raises:
            OrderNotFoundError: If no matching order exists.
        """
        order = self.state.find_order(str(order_id))
        if order is None:
            raise OrderNotFoundError(f"Paper: order {order_id!r} not found.")

        if order[Order.STATUS] not in (Status.PENDING, Status.OPEN):
            return None

        engine = self._get_engine(int(order[Order.TOKEN]))
        engine.deregister(order)
        order[Order.CANCELLED_QTY] = order[Order.REMAINING_QTY]
        order[Order.REMAINING_QTY] = 0
        order[Order.STATUS] = Status.CANCELLED
        order[Order.TIMESTAMP] = datetime.now().replace(microsecond=0)
        return None

    def square_off_position(
        self,
        symbol: str,
        token: int,
        exchange: str,
        quantity: int,
        product: str,
        unique_id: str = "PaperSqOff",
    ) -> dict[str, Any]:
        """Square off (reduce or close) an open position.

        Places an offsetting market order on the opposite side of the current
        net position for the requested quantity.

        Args:
            symbol: Symbol of the position to square off.
            token: Instrument token of the position.
            exchange: Exchange the instrument trades on.
            quantity: Quantity to square off; must be positive and no greater
                than the absolute open net quantity.
            product: Product code for the offsetting order.
            unique_id: Order tag for the offsetting order.

        Returns:
            A dict with the offsetting order's id under ``Order.ID``.

        Raises:
            OrderNotFoundError: If there is no position for ``symbol``.
            InvalidOrderError: If the position is flat or the quantity exceeds
                the open net quantity.
            InputError: If the quantity is not positive.
        """
        request = {
            "symbol": symbol,
            "token": token,
            "exchange": exchange,
            "quantity": quantity,
            "product": product,
            "unique_id": unique_id,
        }
        return self._execute(
            "square_off_position",
            request,
            lambda: self._square_off_position(
                symbol=symbol,
                token=token,
                exchange=exchange,
                quantity=quantity,
                product=product,
                unique_id=unique_id,
            ),
        )

    def _square_off_position(
        self,
        symbol: str,
        token: int,
        exchange: str,
        quantity: int,
        product: str,
        unique_id: str = "PaperSqOff",
    ) -> dict[str, Any]:
        """Validate the request and place the offsetting order.

        Implements the logic behind :meth:`square_off_position`: it checks the
        position exists and is non-flat, sizes and sides the offsetting order,
        and delegates to :meth:`_place_order`.

        Args:
            symbol: Symbol of the position to square off.
            token: Instrument token of the position.
            exchange: Exchange the instrument trades on.
            quantity: Quantity to square off.
            product: Product code for the offsetting order.
            unique_id: Order tag for the offsetting order.

        Returns:
            A dict with the offsetting order's id under ``Order.ID``.

        Raises:
            OrderNotFoundError: If there is no position for ``symbol``.
            InvalidOrderError: If the position is flat or the quantity exceeds
                the open net quantity.
            InputError: If the quantity is not positive.
        """
        position = self.state.positions.get(symbol)
        if position is None:
            raise OrderNotFoundError(
                f"Paper: no position to square off for {symbol!r}."
            )
        net = position[Position.NET_QTY]
        if net == 0:
            raise InvalidOrderError(
                f"Paper: position for {symbol!r} is already flat."
            )
        if int(quantity) <= 0:
            raise InputError("Paper: square-off quantity must be greater than 0.")
        if int(quantity) > abs(int(net)):
            raise InvalidOrderError(
                f"Paper: square-off quantity {quantity} exceeds open net "
                f"quantity {abs(int(net))} for {symbol!r}."
            )

        side = Side.SELL if net > 0 else Side.BUY
        token_dict = {
            "Token": int(token),
            "Symbol": symbol,
            "Exchange": exchange,
        }
        return self._place_order(
            token_dict=token_dict,
            quantity=int(quantity),
            side=side,
            product=product,
            validity=Validity.DAY,
            variety=Variety.REGULAR,
            unique_id=unique_id,
        )

    # ── Reads ─────────────────────────────────────────────────────────────

    def fetch_orderbook(self) -> list[dict[str, Any]]:
        """Return every order placed this session in unified format.

        Returns:
            Deep copies of all order records, in placement order.
        """
        return self._execute("fetch_orderbook", {}, self._fetch_orderbook)

    def _fetch_orderbook(self) -> list[dict[str, Any]]:
        """Return deep copies of all session orders.

        Returns:
            Deep copies of every order record in the book.
        """
        return [deepcopy(o) for o in self.state.orderbook]

    def fetch_tradebook(self) -> list[dict[str, Any]]:
        """Return the filled orders from this session in unified format.

        Returns:
            Deep copies of the order records currently in ``Status.FILLED``.
        """
        return self._execute("fetch_tradebook", {}, self._fetch_tradebook)

    def _fetch_tradebook(self) -> list[dict[str, Any]]:
        """Return deep copies of the filled orders from this session.

        Returns:
            Deep copies of the order records currently in ``Status.FILLED``.
        """
        return [
            deepcopy(o)
            for o in self.state.orderbook
            if o[Order.STATUS] == Status.FILLED
        ]

    def fetch_order(self, order_id: str) -> dict[str, Any]:
        """Return a single order by id in unified format.

        Args:
            order_id: Id of the order to fetch.

        Returns:
            A deep copy of the matching order record.

        Raises:
            OrderNotFoundError: If no matching order exists.
        """
        return self._execute(
            "fetch_order",
            {"order_id": order_id},
            lambda: self._fetch_order(order_id),
        )

    def _fetch_order(self, order_id: str) -> dict[str, Any]:
        """Look up an order by id and return a deep copy.

        Args:
            order_id: Id of the order to fetch.

        Returns:
            A deep copy of the matching order record.

        Raises:
            OrderNotFoundError: If no matching order exists.
        """
        order = self.state.find_order(str(order_id))
        if order is None:
            raise OrderNotFoundError(f"Paper: order {order_id!r} not found.")
        return deepcopy(order)

    def fetch_order_history(self, order_id: str) -> list[dict[str, Any]]:
        """Return the status history for a single order.

        Paper mode keeps only the current state, so the history contains a
        single snapshot of the order.

        Args:
            order_id: Id of the order to fetch.

        Returns:
            A single-element list with a deep copy of the order record.

        Raises:
            OrderNotFoundError: If no matching order exists.
        """
        return self._execute(
            "fetch_order_history",
            {"order_id": order_id},
            lambda: [self._fetch_order(order_id)],
        )

    def fetch_positions(self) -> list[dict[str, Any]]:
        """Return the current open and closed positions in unified format.

        Returns:
            Deep copies of every tracked position record.
        """
        return self._execute("fetch_positions", {}, self._fetch_positions)

    def _fetch_positions(self) -> list[dict[str, Any]]:
        """Return deep copies of every tracked position.

        Returns:
            Deep copies of the position records.
        """
        return [deepcopy(p) for p in self.state.positions.values()]

    def fetch_holdings(self) -> list[dict[str, Any]]:
        """Return holdings in unified format.

        Paper mode does not model T+1 settlement, so holdings mirror the
        current positions.

        Returns:
            Deep copies of the position records, treated as holdings.
        """
        # No T+1 settlement modelling in paper mode; treat positions as holdings.
        return self._execute("fetch_holdings", {}, self._fetch_positions)

    def fetch_margin_limits(self) -> dict[str, Any]:
        """Return the account RMS / margin limits in unified format.

        Returns:
            A deep copy of the synthetic RMS record.
        """
        return self._execute("fetch_margin_limits", {}, self._fetch_margin_limits)

    def _fetch_margin_limits(self) -> dict[str, Any]:
        """Return a deep copy of the synthetic RMS record.

        Returns:
            A deep copy of the RMS record.
        """
        return deepcopy(self.state.rms)

    def fetch_profile(self) -> dict[str, Any]:
        """Return the account profile in unified format.

        Returns:
            A deep copy of the synthetic profile record.
        """
        return self._execute("fetch_profile", {}, self._fetch_profile)

    def _fetch_profile(self) -> dict[str, Any]:
        """Return a deep copy of the synthetic profile record.

        Returns:
            A deep copy of the profile record.
        """
        return deepcopy(self.state.profile_data)

    # ── Helpers ───────────────────────────────────────────────────────────

    def _get_engine(self, token: int) -> MatchingEngine:
        """Return the matching engine for a token, creating it on first use.

        Args:
            token: Instrument token to fetch (or create) an engine for.

        Returns:
            The :class:`MatchingEngine` bound to ``token``.
        """
        engine = self.engines.get(token)
        if engine is None:
            engine = MatchingEngine(token)
            self.engines[token] = engine
        return engine

    @staticmethod
    def _validate_order_inputs(
        quantity: int,
        price: float = 0.0,
        trigger: float = 0.0,
        target: float = 0.0,
        stoploss: float = 0.0,
        trailing_sl: float = 0.0,
    ) -> None:
        """Validate order quantity and price fields.

        Args:
            quantity: Order quantity; must be greater than zero.
            price: Limit price; must be non-negative.
            trigger: Stop trigger price; must be non-negative.
            target: Bracket target price; must be non-negative.
            stoploss: Bracket stop-loss price; must be non-negative.
            trailing_sl: Bracket trailing stop-loss; must be non-negative.

        Raises:
            InputError: If the quantity is not positive or any price field is
                negative.
        """
        if int(quantity) <= 0:
            raise InputError("Paper: order quantity must be greater than 0.")

        values = {
            "price": price,
            "trigger": trigger,
            "target": target,
            "stoploss": stoploss,
            "trailing_sl": trailing_sl,
        }
        for field_name, value in values.items():
            if float(value) < 0:
                raise InputError(f"Paper: order {field_name} must be non-negative.")

    @staticmethod
    def _validate_side(side: str) -> None:
        """Validate that ``side`` is a recognised order side.

        Args:
            side: Order side to check.

        Raises:
            InputError: If ``side`` is not ``Side.BUY`` or ``Side.SELL``.
        """
        if side not in (Side.BUY, Side.SELL):
            raise InputError(
                f"Paper: invalid side {side!r}; expected {Side.BUY!r} or "
                f"{Side.SELL!r}."
            )

    @staticmethod
    def _validate_order_type(order_type: str) -> None:
        """Validate that ``order_type`` is a recognised order type.

        Args:
            order_type: Order type to check.

        Raises:
            InputError: If ``order_type`` is not one of MARKET, LIMIT, SL, or
                SLM.
        """
        valid_types = (
            OrderType.MARKET,
            OrderType.LIMIT,
            OrderType.SL,
            OrderType.SLM,
        )
        if order_type not in valid_types:
            raise InputError(
                f"Paper: invalid order_type {order_type!r}; expected one of "
                f"{list(valid_types)!r}."
            )

    @staticmethod
    def _resolve_order_type(price: float, trigger: float) -> str:
        """Infer the order type from the presence of price and trigger.

        The mapping is: trigger only -> SL-M, neither -> MARKET, price only ->
        LIMIT, both -> SL.

        Args:
            price: Limit price (zero/falsy means unset).
            trigger: Stop trigger price (zero/falsy means unset).

        Returns:
            The resolved ``OrderType`` constant.
        """
        if not price and trigger:
            return OrderType.SLM
        if not price:
            return OrderType.MARKET
        if not trigger:
            return OrderType.LIMIT
        return OrderType.SL

    def _validate_stop_against_ltp(
        self,
        order_type: str,
        side: str,
        price: float,
        trigger: float,
        engine: MatchingEngine,
    ) -> None:
        """Mimic Nautilus' ``reject_stop_orders`` rule.

        Stops priced through the market on submit are rejected so users
        catch the bug in paper mode rather than discover it live. The check
        is skipped entirely when ``reject_invalid_stops`` is ``False`` or the
        order is not a stop.

        Args:
            order_type: Order type being submitted; only SL and SL-M are
                checked.
            side: Order side, ``Side.BUY`` or ``Side.SELL``.
            price: Limit price of the (SL) order.
            trigger: Stop trigger price.
            engine: Matching engine supplying the current LTP.

        Raises:
            InvalidOrderError: If the trigger is on the wrong side of the LTP,
                or an SL limit price is on the wrong side of its trigger.
        """
        if not self.reject_invalid_stops:
            return
        if order_type not in (OrderType.SL, OrderType.SLM):
            return

        ltp = engine.tick.ltp
        if ltp is not None:
            if side == Side.BUY and trigger <= ltp:
                raise InvalidOrderError(
                    f"Paper: BUY {order_type} trigger {trigger} at or below LTP {ltp}."
                )
            if side == Side.SELL and trigger >= ltp:
                raise InvalidOrderError(
                    f"Paper: SELL {order_type} trigger {trigger} at or above LTP {ltp}."
                )

        if order_type == OrderType.SL:
            if side == Side.BUY and price < trigger:
                raise InvalidOrderError(
                    f"Paper: BUY SL price {price} must be >= trigger {trigger}."
                )
            if side == Side.SELL and price > trigger:
                raise InvalidOrderError(
                    f"Paper: SELL SL price {price} must be <= trigger {trigger}."
                )

    @staticmethod
    def _force_fill(
        order: dict[str, Any],
        engine: MatchingEngine,
        fallback_price: float,
    ) -> None:
        """Fill an order in full immediately, bypassing the matching loop.

        Used for market orders with a known price and for the
        ``force_status`` escape hatch. The fill price is the engine's current
        LTP when available, otherwise ``fallback_price``.

        Args:
            order: Order record to fill; mutated in place.
            engine: Matching engine whose LTP is preferred for the fill price.
            fallback_price: Price to use when the engine has no LTP yet.
        """
        fill_px = float(engine.tick.ltp if engine.tick.ltp is not None else fallback_price)
        order[Order.AVG_PRICE] = fill_px
        order[Order.PRICE] = fill_px or order[Order.PRICE]
        order[Order.FILLED_QTY] = order[Order.QUANTITY]
        order[Order.REMAINING_QTY] = 0
        order[Order.STATUS] = Status.FILLED
        order[Order.TIMESTAMP] = datetime.now().replace(microsecond=0)

    def _build_order(
        self,
        token_dict: dict[str, Any],
        quantity: int,
        side: str,
        product: str,
        validity: str,
        variety: str,
        unique_id: str,
        price: float,
        trigger: float,
        target: float,
        stoploss: float,
        trailing_sl: float,
        order_type: str,
    ) -> dict[str, Any]:
        """Assemble a fresh unified order record with a unique paper id.

        Args:
            token_dict: Instrument metadata; must contain ``"Token"`` and may
                contain ``"Symbol"`` and ``"Exchange"``.
            quantity: Order quantity.
            side: Order side, ``Side.BUY`` or ``Side.SELL``.
            product: Product code.
            validity: Order validity.
            variety: Order variety.
            unique_id: Caller-supplied tag stored as the user order id.
            price: Limit price.
            trigger: Stop trigger price.
            target: Bracket target price.
            stoploss: Bracket stop-loss price.
            trailing_sl: Bracket trailing stop-loss.
            order_type: Resolved order type for the record.

        Returns:
            A new unified order record in ``Status.PENDING`` with a generated
            ``Order.ID``.
        """
        exchange = token_dict.get("Exchange", "")
        return {
            Order.ID: f"PAPER{time.time_ns()}",
            Order.USER_ID: unique_id,
            Order.TIMESTAMP: datetime.now().replace(microsecond=0),
            Order.SYMBOL: token_dict.get("Symbol", ""),
            Order.TOKEN: int(token_dict["Token"]),
            Order.SIDE: side,
            Order.TYPE: order_type,
            Order.AVG_PRICE: 0.0,
            Order.PRICE: float(price),
            Order.TRIGGER_PRICE: float(trigger),
            Order.TARGET_PRICE: float(target),
            Order.STOPLOSS_PRICE: float(stoploss),
            Order.TRAILING_STOPLOSS: float(trailing_sl),
            Order.QUANTITY: int(quantity),
            Order.FILLED_QTY: 0,
            Order.REMAINING_QTY: int(quantity),
            Order.CANCELLED_QTY: 0,
            Order.STATUS: Status.PENDING,
            Order.REJECT_REASON: "",
            Order.DISCLOSED_QUANTITY: 0,
            Order.PRODUCT: product,
            Order.EXCHANGE: exchange,
            Order.SEGMENT: exchange,
            Order.VALIDITY: validity,
            Order.VARIETY: variety,
            Order.INFO: {"broker": self.broker_id, "mode": "paper"},
        }
