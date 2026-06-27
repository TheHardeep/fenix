"""
Fenix Trading Library
====================
A Python library for trading in the Indian Finance Sector with support for 15+ broker APIs.

Documentation is available in the docstrings and
online at https://github.com/TheHardeep/fenix/wiki.

Examples are available at https://github.com/TheHardeep/fenix#examples

:copyright: (c) 2024 by Hardeep Singh.
:license: GPLv3, see LICENSE for more details.
"""

#  ------------------------------------------------------------------------------


__version__ = "2.0.2"


#  ------------------------------------------------------------------------------

# Base class
from fenix.base.broker import Broker  # noqa: F401

# Errors & constants — re-export each submodule's curated public API.
# Each `import *` honours that module's own `__all__`, keeping it the single
# source of truth so `fenix.__all__` can never advertise an unbound name.
from fenix.base import errors, constants  # noqa: F401
from fenix.base.errors import *  # noqa: F401,F403
from fenix.base.constants import *  # noqa: F401,F403


# Broker adapters — kept explicit (no per-broker __all__) for clear, statically
# analysable imports. `brokers` is derived from the classes below to avoid drift.
from fenix.aliceblue import AliceBlue  # noqa: F401
from fenix.angelone import AngelOne  # noqa: F401
from fenix.anandrathi import AnandRathi  # noqa: F401
from fenix.dhan import Dhan  # noqa: F401
from fenix.finvasia import Finvasia  # noqa: F401
from fenix.fivepaisa import FivePaisa  # noqa: F401
from fenix.fyers import Fyers  # noqa: F401
from fenix.groww import Groww  # noqa: F401
from fenix.iifl import Iifl  # noqa: F401
from fenix.kotakneo import KotakNeo  # noqa: F401
from fenix.mastertrust import MasterTrust  # noqa: F401
from fenix.motilaloswal import MotilalOswal  # noqa: F401
from fenix.symphony import Symphony  # noqa: F401
from fenix.upstox import Upstox  # noqa: F401
from fenix.zerodha import Zerodha  # noqa: F401


# Public registry of available brokers (ccxt-style: list of class names),
# derived from the imported classes so it stays in sync automatically.
brokers = [
    cls.__name__
    for cls in (
        AliceBlue,
        AngelOne,
        AnandRathi,
        Dhan,
        Finvasia,
        FivePaisa,
        Fyers,
        Groww,
        Iifl,
        KotakNeo,
        MasterTrust,
        MotilalOswal,
        Symphony,
        Upstox,
        Zerodha,
    )
]


__all__ = (
    ["Broker", "brokers", "errors", "constants"]
    + errors.__all__
    + constants.__all__
    + brokers
)
