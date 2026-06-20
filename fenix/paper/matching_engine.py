"""Per-instrument paper-trading matching engine.

One :class:`MatchingEngine` per token holds the resting orders for that
instrument and the latest tick snapshot. Ticks are pushed in via
:meth:`on_tick`; resting orders are walked and any that should fill are
returned so the caller can update positions and emit fill events.

The engine implements the trigger-then-convert pattern for SL / SL-M
orders: a stop sits at ``Status.PENDING`` until the trigger is crossed,
at which point it converts to a working LIMIT (for SL) or fills at the
market (for SL-M).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fenix.base.constants import Order, OrderType, Side, Status


class TickState:
    """Latest tick snapshot for an instrument."""

    __slots__ = ("ltp", "bid", "ask")

    def __init__(self) -> None:
        """Initialize an empty snapshot with last price, bid and ask unset."""
        self.ltp: float | None = None
        self.bid: float | None = None
        self.ask: float | None = None

    def update(
        self,
        ltp: float | None = None,
        bid: float | None = None,
        ask: float | None = None,
    ) -> None:
        """Merge new tick values into the snapshot.

        Only the fields supplied with a non-``None`` value are overwritten,
        so a tick carrying just an LTP leaves the existing bid/ask intact.

        Args:
            ltp: Last traded price, or ``None`` to leave it unchanged.
            bid: Best bid price, or ``None`` to leave it unchanged.
            ask: Best ask price, or ``None`` to leave it unchanged.
        """
        if ltp is not None:
            self.ltp = float(ltp)
        if bid is not None:
            self.bid = float(bid)
        if ask is not None:
            self.ask = float(ask)


class MatchingEngine:
    """Resting-order book and matching loop for one instrument."""

    def __init__(self, token: int) -> None:
        """Initialize an empty book for a single instrument.

        Args:
            token: Instrument token this engine matches orders for.
        """
        self.token = int(token)
        self.tick = TickState()
        self.resting: list[dict[str, Any]] = []

    # ── Resting-order management ──────────────────────────────────────────

    def register(self, order: dict[str, Any]) -> None:
        """Add an order to the resting book so future ticks can fill it.

        Args:
            order: Unified order record to start resting in the book.
        """
        self.resting.append(order)

    def deregister(self, order: dict[str, Any]) -> None:
        """Remove an order from the resting book.

        The call is a no-op if the order is not currently resting (for
        example, it already filled or was never registered).

        Args:
            order: Unified order record to remove from the book.
        """
        try:
            self.resting.remove(order)
        except ValueError:
            pass

    # ── Tick processing ───────────────────────────────────────────────────

    def on_tick(
        self,
        ltp: float | None = None,
        bid: float | None = None,
        ask: float | None = None,
    ) -> list[dict[str, Any]]:
        """Update the tick and return orders newly filled on this tick.

        Walks every resting order once against the refreshed tick and
        removes any that fill, leaving the rest to rest for later ticks.

        Args:
            ltp: Last traded price for this tick.
            bid: Best bid price for this tick (optional).
            ask: Best ask price for this tick (optional).

        Returns:
            The order records that moved to ``Status.FILLED`` on this tick,
            in the order they filled.
        """
        self.tick.update(ltp=ltp, bid=bid, ask=ask)
        newly_filled: list[dict[str, Any]] = []

        for order in list(self.resting):
            if self._try_match(order):
                newly_filled.append(order)
                self.resting.remove(order)

        return newly_filled

    def _try_match(self, order: dict[str, Any]) -> bool:
        """Attempt to fill ``order`` against the current tick.

        Implements the trigger-then-convert state machine: a resting SL/SL-M
        stop stays pending until its trigger is crossed, then either fills at
        market (SL-M) or converts to a working limit (SL); market orders fill
        immediately and limit orders fill once the price is favourable.

        Args:
            order: Resting order record to evaluate against the tick.

        Returns:
            ``True`` if the order moved to ``Status.FILLED`` on this tick,
            otherwise ``False``.
        """
        side = order[Order.SIDE]
        order_type = order[Order.TYPE]
        status = order[Order.STATUS]

        if status == Status.PENDING and order_type in (OrderType.SL, OrderType.SLM):
            if not self._is_triggered(order, side):
                return False
            if order_type == OrderType.SLM:
                return self._fill_at_market(order)
            order[Order.TYPE] = OrderType.LIMIT
            order[Order.STATUS] = Status.OPEN
            order_type = OrderType.LIMIT
            status = Status.OPEN

        if status == Status.PENDING and order_type == OrderType.MARKET:
            return self._fill_at_market(order)

        if status == Status.OPEN and order_type == OrderType.LIMIT:
            if self._limit_can_fill(order, side):
                return self._fill_at_limit(order)

        return False

    # ── Fill primitives ───────────────────────────────────────────────────

    def _fill_at_market(self, order: dict[str, Any]) -> bool:
        """Fill an order in full at the current last traded price.

        Args:
            order: Order record to mark filled; mutated in place.

        Returns:
            ``True`` once the order is filled, or ``False`` if no LTP is
            available yet to price the fill.
        """
        ltp = self.tick.ltp
        if ltp is None:
            return False
        order[Order.AVG_PRICE] = ltp
        order[Order.PRICE] = ltp
        order[Order.FILLED_QTY] = order[Order.QUANTITY]
        order[Order.REMAINING_QTY] = 0
        order[Order.STATUS] = Status.FILLED
        order[Order.TIMESTAMP] = datetime.now().replace(microsecond=0)
        return True

    def _fill_at_limit(self, order: dict[str, Any]) -> bool:
        """Fill a marketable limit order at the current last traded price.

        Callers are expected to confirm the limit is marketable via
        :meth:`_limit_can_fill` before invoking this method.

        Args:
            order: Order record to mark filled; mutated in place.

        Returns:
            ``True`` once the order is filled, or ``False`` if no LTP is
            available yet to price the fill.
        """
        ltp = self.tick.ltp
        if ltp is None:
            return False
        order[Order.AVG_PRICE] = ltp
        order[Order.FILLED_QTY] = order[Order.QUANTITY]
        order[Order.REMAINING_QTY] = 0
        order[Order.STATUS] = Status.FILLED
        order[Order.TIMESTAMP] = datetime.now().replace(microsecond=0)
        return True

    # ── Trigger / fill conditions ─────────────────────────────────────────

    def _is_triggered(self, order: dict[str, Any], side: str) -> bool:
        """Check whether a stop order's trigger has been crossed.

        A buy stop triggers once the price rises to its trigger; a sell stop
        triggers once the price falls to its trigger.

        Args:
            order: Stop order whose ``TRIGGER_PRICE`` is being tested.
            side: Order side, one of ``Side.BUY`` or ``Side.SELL``.

        Returns:
            ``True`` if the current LTP has crossed the trigger, otherwise
            ``False`` (including when no LTP is available yet).
        """
        if self.tick.ltp is None:
            return False
        trigger = float(order[Order.TRIGGER_PRICE])
        if side == Side.BUY:
            return self.tick.ltp >= trigger
        return self.tick.ltp <= trigger

    def _limit_can_fill(self, order: dict[str, Any], side: str) -> bool:
        """Check whether a limit order is marketable at the current tick.

        A buy limit is marketable once the price trades at or below its
        limit; a sell limit once the price trades at or above its limit.

        Args:
            order: Limit order whose ``PRICE`` is being tested.
            side: Order side, one of ``Side.BUY`` or ``Side.SELL``.

        Returns:
            ``True`` if the current LTP makes the limit marketable, otherwise
            ``False`` (including when no LTP is available yet).
        """
        if self.tick.ltp is None:
            return False
        price = float(order[Order.PRICE])
        if side == Side.BUY:
            return self.tick.ltp <= price
        return self.tick.ltp >= price
