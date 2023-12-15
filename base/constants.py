__all__ = [
    "Side",
    "Root",
    "WeeklyExpiry",
    "OrderType",
    "ExchangeCode",
    "Product",
    "Validity",
    "Variety",
    "Status",
    "Order",
    "Position",
    "Profile",
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
    BANKNIFTY & NIFTY Constants.
    """
    BNF = "BANKNIFTY"
    NF = "NIFTY"
    FNF = "FINNIFTY"
    MIDCPNF = "MIDCPNIFTY"


class WeeklyExpiry:
    """
    Weekly Expiry Constants.
    """
    CURRENT = "CURRENT"
    NEXT = "NEXT"
    FAR = "FAR"
    EXPIRY = "Expiry"
    LOTSIZE = "LotSize"


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
    BCO = "BCO"  # BSE Commodities
    BCD = "BCD"  #
    MCX = "MCX"  # Multi Commodity Exchange F&O
    CDS = "CDS"  #


class Product:
    """
    Product Type Constants.
    """
    CNC = "CNC"
    NRML = "NRML"
    MARGIN = "MARGIN"
    MIS = "MIS"
    BO = "BO"
    CO = "CO"
    SM = "SM"  # SuperMutilple


class Validity:
    """
    Order Validity Constnats.
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
    PARTIALLYFILLED = "PARTIALLYFILLED"
    FILLED = "FILLED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    MODIFIED = "MODIFIED"


class Order:
    """
    Unified Order Response Dicitonary Keys Constants.
    """
    ID = "id"
    USERID = "userOrderId"
    CLIENTID = "clientId"
    TIMESTAMP = 'timestamp'
    SYMBOL = "symbol"
    TOKEN = "token"
    SIDE = "side"
    TYPE = "type"
    AVGPRICE = "avgPrice"
    PRICE = "price"
    TRIGGERPRICE = "triggerPrice"
    TARGETPRICE = "targetPrice"
    STOPLOSSPRICE = "stoplossPrice"
    TRAILINGSTOPLOSS = "trailingStoploss"
    QUANTITY = "quantity"
    FILLEDQTY = "filled"
    REMAININGQTY = "remaining"
    CANCELLEDQTY = "cancelleldQty"
    STATUS = "status"
    REJECTREASON = "rejectReason"
    DISCLOSEDQUANTITY = "disclosedQuantity"
    PRODUCT = "product"
    SEGMENT = "segment"
    EXCHANGE = "exchange"
    VALIDITY = "validity"
    VARIETY = "variety"
    INFO = "info"


class Position:
    """
    Unified Account Positions Response Dicitonary Keys Constants.
    """
    SYMBOL = "symbol"
    TOKEN = "token"
    NETQTY = "netQty"
    AVGPRICE = "avgPrice"
    MTM = "mtm"
    PNL = "pnl"
    BUYQTY = "buyQty"
    BUYPRICE = "buyPrice"
    SELLQTY = "sellQty"
    SELLPRICE = "sellPrice"
    LTP = "ltp"
    PRODUCT = "product"
    EXCHANGE = "exchange"
    INFO = "info"


class Profile:
    """
    Unified Account Profile Response Dicitonary Keys Constants.
    """
    CLIENTID = "clientId"
    NAME = "name"
    EMAILID = "emailId"
    MOBILENO = "mobileNo"
    PAN = "pan"
    ADDRESS = "address"
    BANKNAME = "bankName"
    BANKBRANCHNAME = "bankBranchName"
    BANKACCNO = "bankAccNo"
    EXHCNAGESENABLED = "exchangesEnabled"
    ENABLED = "enabled"
    INFO = "info"


class UniqueID:
    """
    Default Unique Order ID Constants.
    """
    MARKETORDER = "MarketOrder"
    LIMITORDER = "LIMITOrder"
    SLORDER = "SLOrder"
    SLMORDER = "SLMOrder"
    MARKETORDERNO = 101
    LIMITORDERNO = 102
    SLORDERNO = 102
    SLMORDERNO = 103
