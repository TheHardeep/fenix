__all__ = [
    "Side",
    "Root",
    "WeeklyExpiry",
    "Option",
    "OrderType",
    "ExchangeCode",
    "Product",
    "Validity",
    "Variety",
    "Status",
    "Order",
    "Position",
    "Profile",
    "RMS",
    "UniqueID",
]


class Side:
    """
    Order Side Constants.
    """

    BUY = "BUY"
    SELL = "SELL"


class Root:
    """
    Underlying (root) symbol constants for indices and commodities.
    """

    BNF = "BANKNIFTY"
    NF = "NIFTY"
    FNF = "FINNIFTY"
    MIDCPNF = "MIDCPNIFTY"
    SENSEX = "SENSEX"
    BANKEX = "BANKEX"

    SILVER = "SILVER"
    SILVERM = "SILVERM"
    GOLD = "GOLD"
    GOLDM = "GOLDM"
    COPPER = "COPPER"
    ZINC = "ZINC"
    NATURALGAS = "NATURALGAS"
    NATGASMINI = "NATGASMINI"
    CRUDEOIL = "CRUDEOIL"
    CRUDEOILM = "CRUDEOILM"


class WeeklyExpiry:
    """
    Weekly Expiry Constants.
    """

    CURRENT = "CURRENT"
    NEXT = "NEXT"
    FAR = "FAR"
    EXPIRY = "Expiry"
    LOT_SIZE = "LotSize"


class Option:
    """
    Trading Options
    """

    CE = "CE"
    PE = "PE"


class OrderType:
    """
    Order Type Constants.
    """

    MARKET = "MARKET"
    LIMIT = "LIMIT"
    SLM = "SLM"
    SL = "SL"


class ExchangeCode:
    """
    Exchange Code Constants.
    """

    NSE = "NSE"  # NSE Equity
    NFO = "NFO"  # NSE F&O
    BSE = "BSE"  # BSE Equity
    BFO = "BFO"  # BSE F&O
    NCO = "NCO"  # NSE Commodities
    BCD = "BCD"  #
    MCX = "MCX"  # Multi Commodity Exchange F&O
    CDS = "NCD"  #
    NCX = "NCDEX"


class Product:
    """
    Product Type Constants.
    """

    CNC = "CNC"
    NRML = "NRML"
    MARGIN = "MARGIN"
    MTF = "MTF"
    MIS = "MIS"
    BO = "BO"
    CO = "CO"
    SM = "SM"  # SuperMutilple


class Validity:
    """
    Order Validity Constants.
    """

    DAY = "DAY"
    IOC = "IOC"
    GTD = "GTD"
    GTC = "GTC"
    FOK = "FOK"
    TTL = "TTL"


class Variety:
    """
    Order Variety Constants.
    """

    REGULAR = "REGULAR"
    STOPLOSS = "STOPLOSS"
    AMO = "AMO"
    BO = "BO"
    CO = "CO"
    ICEBERG = "ICEBERG"
    AUCTION = "AUCTION"


class Status:
    """
    Order Status Constants.
    """

    PENDING = "PENDING"
    OPEN = "OPEN"
    PARTIALLY_FILLED = "PARTIALLY_FILLED"
    FILLED = "FILLED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    MODIFIED = "MODIFIED"


class Order:
    """
    Unified Order Response Dictionary Keys Constants.
    """

    ID = "id"
    USER_ID = "userOrderId"
    CLIENT_ID = "clientId"
    TIMESTAMP = "timestamp"
    SYMBOL = "symbol"
    TOKEN = "token"
    EXCHANGE_TOKEN = "exchangeToken"
    SIDE = "side"
    TYPE = "type"
    AVG_PRICE = "avgPrice"
    PRICE = "price"
    TRIGGER_PRICE = "triggerPrice"
    TARGET_PRICE = "targetPrice"
    STOPLOSS_PRICE = "stoplossPrice"
    TRAILING_STOPLOSS = "trailingStoploss"
    QUANTITY = "quantity"
    FILLED_QTY = "filled"
    REMAINING_QTY = "remaining"
    CANCELLED_QTY = "cancelledQty"
    STATUS = "status"
    REJECT_REASON = "rejectReason"
    DISCLOSED_QUANTITY = "disclosedQuantity"
    PRODUCT = "product"
    SEGMENT = "segment"
    EXCHANGE = "exchange"
    VALIDITY = "validity"
    VARIETY = "variety"
    INFO = "info"


class Position:
    """
    Unified Account Positions Response Dictionary Keys Constants.
    """

    SYMBOL = "symbol"
    TOKEN = "token"
    NET_QTY = "netQty"
    AVG_PRICE = "avgPrice"
    MTM = "mtm"
    PNL = "pnl"
    REALISED_PNL = "realisedPnl"
    UNREALISED_PNL = "unrealisedPnl"
    BUY_QTY = "buyQty"
    BUY_PRICE = "buyPrice"
    SELL_QTY = "sellQty"
    SELL_PRICE = "sellPrice"
    LTP = "ltp"
    PRODUCT = "product"
    EXCHANGE = "exchange"
    INFO = "info"


class Profile:
    """
    Unified Account Profile Response Dictionary Keys Constants.
    """

    CLIENT_ID = "clientId"
    NAME = "name"
    EMAIL_ID = "emailId"
    MOBILE_NO = "mobileNo"
    PAN = "pan"
    ADDRESS = "address"
    BANK_NAME = "bankName"
    BANK_BRANCH_NAME = "bankBranchName"
    BANK_ACC_NO = "bankAccNo"
    EXCHANGES_ENABLED = "exchangesEnabled"
    ENABLED = "enabled"
    INFO = "info"


class RMS:
    """
    Unified Account RMS Response Dictionary Keys Constants.
    """
    MARGINUSED = "marginUsed"
    MARGINAVAIL = "marginAvail"
    CASHMARGIN = "cashMargin"
    SPANMARGIN = "spanMargin"
    VARIABLEMARGIN = "variableMargin"
    COLLATERAL = "collateral"
    INFO = "info"


class UniqueID:
    """
    Default Unique Order ID Constants.
    """

    DEF_ORDER = "FenixOrder"
    MARKET_ORDER = "MarketOrder"
    LIMIT_ORDER = "LIMITOrder"
    SL_ORDER = "SLOrder"
    SLM_ORDER = "SLMOrder"
    DEF_ORDER_NO = 100
    MARKET_ORDER_NO = 101
    LIMIT_ORDER_NO = 102
    SL_ORDER_NO = 103
    SLM_ORDER_NO = 104
