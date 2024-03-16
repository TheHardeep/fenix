#  ------------------------------------------------------------------------------


__version__ = "1.0.0"


#  ------------------------------------------------------------------------------

from fenix.base.exchange import Exchange               # noqa: F401


from fenix.base import errors                          # noqa: F401
from fenix.base.errors import InputError               # noqa: F401
from fenix.base.errors import ResponseError            # noqa: F401
from fenix.base.errors import TokenDownloadError       # noqa: F401
from fenix.base.errors import RequestTimeout           # noqa: F401
from fenix.base.errors import NetworkError             # noqa: F401
from fenix.base.errors import BrokerError              # noqa: F401


from fenix.base import constants                       # noqa: F401
from fenix.base.constants import Side                  # noqa: F401
from fenix.base.constants import Root                  # noqa: F401
from fenix.base.constants import WeeklyExpiry          # noqa: F401
from fenix.base.constants import OrderType             # noqa: F401
from fenix.base.constants import ExchangeCode          # noqa: F401
from fenix.base.constants import Product               # noqa: F401
from fenix.base.constants import Validity              # noqa: F401
from fenix.base.constants import Variety               # noqa: F401
from fenix.base.constants import Status                # noqa: F401
from fenix.base.constants import Order                 # noqa: F401
from fenix.base.constants import Position              # noqa: F401
from fenix.base.constants import Profile               # noqa: F401
from fenix.base.constants import UniqueID              # noqa: F401


from fenix.aliceblue import aliceblue                  # noqa :F401
from fenix.angelone import angelone                    # noqa :F401
from fenix.choice import choice                        # noqa :F401
from fenix.finvasia import finvasia                    # noqa :F401
from fenix.fivepaisa import fivepaisa                  # noqa :F401
from fenix.fyers import fyers                          # noqa :F401
from fenix.iifl import iifl                            # noqa :F401
from fenix.kotak import kotak                          # noqa :F401
from fenix.kotakneo import kotakneo                    # noqa :F401
from fenix.kunjee import kunjee                        # noqa :F401
from fenix.mastertrust import mastertrust              # noqa :F401
from fenix.motilaloswal import motilaloswal            # noqa :F401
from fenix.paper import paper                          # noqa :F401
from fenix.symphony import symphony                    # noqa :F401
from fenix.upstox import upstox                        # noqa :F401
from fenix.vpc import vpc                              # noqa :F401
from fenix.zerodha import zerodha                      # noqa :F401


exchanges = [
    "aliceblue",
    "angelone",
    "choice",
    "finvasia",
    "fivepaisa",
    "fyers",
    "iifl",
    "kotak",
    "kotakneo",
    "kunjee",
    "mastertrust",
    "motilaloswal",
    "paper",
    "symphony",
    "upstox",
    "vpc",
    "zerodha",
]

base = [
    "Exchange",
    "exchanges",
    "constants",
]

__all__ = base + errors.__all__ + exchanges + constants.__all__
