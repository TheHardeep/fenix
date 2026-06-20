"""Paper-trading subpackage.

Use a broker in paper mode by passing ``paper_mode=True`` in its config::

    broker = AliceBlue({"paper_mode": True})
    broker.authenticate()                # no-op in paper mode
    broker.market_buy_order(token_dict, quantity=1, unique_id="t1")
    broker.on_tick(token=12345, ltp=2500.0)   # drives fills
    broker.fetch_positions()
"""

from fenix.paper.client import PaperExecutionClient
from fenix.paper.matching_engine import MatchingEngine, TickState
from fenix.paper.state import PaperState

__all__ = [
    "PaperExecutionClient",
    "MatchingEngine",
    "TickState",
    "PaperState",
]
