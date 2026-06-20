"""Shared in-memory state for paper-traded orders, positions and account.

A single :class:`PaperState` is held by each broker's :class:`PaperExecutionClient`.
All read methods (``fetch_orderbook``, ``fetch_positions``, ``rms_limits``,
``profile``) are served from this object when the broker is in paper mode.
"""

from __future__ import annotations

from typing import Any

from fenix.base.constants import (
    ExchangeCode,
    Order,
    Position,
    Profile,
    RMS,
    Side,
)


class PaperState:
    """Mutable state for a single paper-trading session."""

    def __init__(
        self,
        broker_id: str = "paper",
        client_id: str = "PAPER001",
        starting_margin: float = 1_000_000.0,
    ) -> None:
        """Initialize an empty session seeded with synthetic account data.

        The order book and positions start empty; the RMS limits and profile
        are pre-populated with placeholder paper-trading values so the read
        methods have something to return before any orders are placed.

        Args:
            broker_id: Identifier of the owning broker, echoed back in the
                ``INFO`` blocks of synthetic records.
            client_id: Client identifier reported by the paper profile.
            starting_margin: Opening available margin for the session.
        """
        self.broker_id = broker_id
        self.client_id = client_id

        self.orderbook: list[dict[str, Any]] = []
        self.positions: dict[str, dict[str, Any]] = {}

        self.rms: dict[str, Any] = {
            RMS.MARGINUSED: 0.0,
            RMS.MARGINAVAIL: float(starting_margin),
            RMS.INFO: {
                "broker": broker_id,
                "mode": "paper",
                "startingMargin": float(starting_margin),
            },
        }

        self.profile_data: dict[str, Any] = {
            Profile.CLIENT_ID: client_id,
            Profile.NAME: "Paper Trader",
            Profile.EMAIL_ID: "paper@fenix.local",
            Profile.MOBILE_NO: "0000000000",
            Profile.PAN: "PAPERPAN00",
            Profile.ADDRESS: "Paper Address",
            Profile.BANK_NAME: "Paper Bank",
            Profile.BANK_BRANCH_NAME: "Paper Branch",
            Profile.BANK_ACC_NO: "0000000000",
            Profile.EXCHANGES_ENABLED: [
                ExchangeCode.NSE,
                ExchangeCode.BSE,
                ExchangeCode.NFO,
                ExchangeCode.BFO,
                ExchangeCode.MCX,
                ExchangeCode.CDS,
            ],
            Profile.ENABLED: True,
            Profile.INFO: {"broker": broker_id, "mode": "paper"},
        }

    # ── Orders ────────────────────────────────────────────────────────────

    def add_order(self, order: dict[str, Any]) -> None:
        """Append an order to the session order book.

        Args:
            order: Unified order record to store.
        """
        self.orderbook.append(order)

    def find_order(self, order_id: str) -> dict[str, Any] | None:
        """Look up a live order record by its id.

        The record is returned by reference so callers can mutate it in
        place (for example, to update status on a fill or cancellation).

        Args:
            order_id: Order id to search for; coerced to ``str`` for matching.

        Returns:
            The matching order record, or ``None`` if no order has that id.
        """
        order_id = str(order_id)
        for order in self.orderbook:
            if order[Order.ID] == order_id:
                return order
        return None

    # ── Positions ─────────────────────────────────────────────────────────

    def update_position_on_fill(self, order: dict[str, Any]) -> None:
        """Apply a filled order to the positions book.

        Opens a new position for the symbol if none exists, then folds the
        fill into the net quantity, buy/sell weighted-average prices, and
        realised PnL, and refreshes MTM. Each fill leg is tracked under
        ``Position.INFO`` so the weighted averages can be recomputed cleanly
        on every fill.

        Args:
            order: A filled order record whose ``FILLED_QTY``, ``AVG_PRICE``,
                and ``SIDE`` drive the position update.
        """
        symbol = order[Order.SYMBOL]
        fill_qty = int(order[Order.FILLED_QTY])
        fill_price = float(order[Order.AVG_PRICE])
        is_buy = order[Order.SIDE] == Side.BUY

        position = self.positions.get(symbol)
        if position is None:
            position = self._new_position(order)
            self.positions[symbol] = position

        previous_net = int(position[Position.NET_QTY])
        previous_avg = float(position[Position.AVG_PRICE] or 0.0)
        realised_pnl = float(position[Position.INFO].get("realised_pnl", 0.0))

        leg_key = "buy_legs" if is_buy else "sell_legs"
        position[Position.INFO][leg_key].append((fill_qty, fill_price))

        legs = position[Position.INFO][leg_key]
        total_qty = sum(qty for qty, _ in legs)
        total_cost = sum(qty * px for qty, px in legs)
        avg_px = total_cost / total_qty if total_qty else 0.0

        if is_buy:
            position[Position.BUY_QTY] = total_qty
            position[Position.BUY_PRICE] = avg_px
        else:
            position[Position.SELL_QTY] = total_qty
            position[Position.SELL_PRICE] = avg_px

        signed_fill_qty = fill_qty if is_buy else -fill_qty
        net = previous_net + signed_fill_qty
        position[Position.NET_QTY] = net

        if previous_net == 0 or (previous_net > 0) == (signed_fill_qty > 0):
            open_cost = abs(previous_net) * previous_avg + fill_qty * fill_price
            position[Position.AVG_PRICE] = open_cost / abs(net)
        else:
            closing_qty = min(abs(previous_net), fill_qty)
            if previous_net > 0:
                realised_pnl += closing_qty * (fill_price - previous_avg)
            else:
                realised_pnl += closing_qty * (previous_avg - fill_price)

            if net == 0:
                position[Position.AVG_PRICE] = 0.0
            elif (previous_net > 0) == (net > 0):
                position[Position.AVG_PRICE] = previous_avg
            else:
                position[Position.AVG_PRICE] = fill_price

        position[Position.INFO]["realised_pnl"] = realised_pnl
        self._recompute_pnl(position)

    def update_ltp(self, token: int, ltp: float) -> None:
        """Update LTP and refresh MTM / PnL for any matching position.

        Args:
            token: Instrument token whose positions should be repriced.
            ltp: New last traded price to apply.
        """
        ltp = float(ltp)
        for position in self.positions.values():
            if int(position[Position.TOKEN]) == int(token):
                position[Position.LTP] = ltp
                self._recompute_pnl(position)

    def _new_position(self, order: dict[str, Any]) -> dict[str, Any]:
        """Build a flat position record seeded from a first fill.

        Args:
            order: The fill that opened the position, used for the symbol,
                token, product, exchange, and initial LTP.

        Returns:
            A new unified position record with zeroed quantities and PnL.
        """
        return {
            Position.SYMBOL: order[Order.SYMBOL],
            Position.TOKEN: int(order[Order.TOKEN]),
            Position.NET_QTY: 0,
            Position.AVG_PRICE: 0.0,
            Position.MTM: 0.0,
            Position.PNL: 0.0,
            Position.BUY_QTY: 0,
            Position.BUY_PRICE: 0.0,
            Position.SELL_QTY: 0,
            Position.SELL_PRICE: 0.0,
            Position.LTP: float(order[Order.AVG_PRICE]),
            Position.PRODUCT: order[Order.PRODUCT],
            Position.EXCHANGE: order[Order.EXCHANGE],
            Position.INFO: {
                "buy_legs": [],
                "sell_legs": [],
                "realised_pnl": 0.0,
            },
        }

    @staticmethod
    def _recompute_pnl(position: dict[str, Any]) -> None:
        """Recompute MTM and total PnL for a position from its current LTP.

        Marks the open quantity to market against the average price and adds
        the stored realised PnL to produce the total. The ``MTM`` and ``PNL``
        fields are updated in place.

        Args:
            position: Position record to reprice; mutated in place.
        """
        ltp = float(position[Position.LTP] or 0.0)
        net = position[Position.NET_QTY]
        avg_px = float(position[Position.AVG_PRICE] or 0.0)
        realised = float(position[Position.INFO].get("realised_pnl", 0.0))

        if net > 0:
            unrealised = net * (ltp - avg_px)
        elif net < 0:
            unrealised = abs(net) * (avg_px - ltp)
        else:
            unrealised = 0.0

        position[Position.MTM] = unrealised
        position[Position.PNL] = realised + unrealised
