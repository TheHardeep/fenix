# Overview

The fenix library is a collection of Indian *brokers* or broker classes. Each class implements the public and private API for a particular broker. All brokers are derived from the base Broker class and share a set of common methods. To access a particular broker from fenix library you need not create an instance of the corresponding broker class as all the methods defined in the classes are class methods. So they can be used by just importing the class and using the method you want. Supported brokers are updated frequently and new brokers are added regularly.

# Brokers

- [Usage](#usage)
- [Paper Broker](#paper-testnet-environment)
- [Common Broker Attrbiutes](#common-broker-attributes)
- [Request Attributes](#request-parameters-attributes)
- [Response Attributes](#response-parameters-attributes)

The Fenix library currently supports the following 16 Indian Brokers and their trading APIs:


| Logo | Id  | Name | Supported |
|------|-----|-----|-----------|
|[<img src='https://global.discourse-cdn.com/business4/uploads/aliceblueonline/original/1X/e83a546773cc49916c1a15f7095ee5185340ddbf.png' width='110'>](https://ant.aliceblueonline.com/)| aliceblue | [AliceBlue](https://ant.aliceblueonline.com/) | 🟢 |
|[<img src='https://w3assets.angelone.in/wp-content/uploads/2023/08/AO-R-Logo.png' width='80'>](https://www.angelone.in/login/?redirectUrl=)| angelone | [AngelOne](https://www.angelone.in/login/?redirectUrl=) | 🟢 |
|[<img src='https://finx.choiceindia.com/assets/images/finx-icons/finx-login-logo.svg' width='80'>](https://finx.choiceindia.com/auth/login)| choice | [Choice](https://finx.choiceindia.com/auth/login) | 🟢 |
|[<img src='https://shoonya.com/static/img/shoonya_logo.1937b07.png' width='80'>](https://shoonya.com/)| finvasia | [Finvasia](https://shoonya.com/) | 🟢 |
|[<img src='https://login.5paisa.com/content/images/5paisa-logo.svg' width='80'>](https://login.5paisa.com/)| fivepaisa | [5paisa](https://login.5paisa.com/) | 🟢 |
|[<img src='https://assets.fyers.in/images/logo.svg' width='80'>](https://login.fyers.in/)| fyers | [Fyers](https://login.fyers.in/) | 🟢 |
|[<img src='https://www.iifl.com/files/2022-04/iifl-securities.webp' width='70'>](https://smartapps.iifl.com/CustomerPortal/Login)| iifl | [IIFL](https://smartapps.iifl.com/CustomerPortal/Login) | 🟢 |
|[<img src='https://www.kotaksecurities.com/trade/9f5989b5a2a4ec74830f.svg' width='140'>](https://www.kotaksecurities.com/trade/login)| kotak | [Kotak](https://www.kotaksecurities.com/trade/login) | 🟢 |
|[<img src='https://www.kotaksecurities.com/trade/26482affd706bc8fc0c2.svg' width='50'>](https://neo.kotaksecurities.com/)| kotakneo| [Kotak Neo](https://neo.kotaksecurities.com/) | 🟢 |
|[<img src='https://www.farsightshares.com/assets/icons/kunjee.png' width='80' height='70'>](https://trade.kunjee.net:3000/#!/app)| kunjee | [Kunjee](https://trade.kunjee.net:3000/#!/app) | 🟢 |
|[<img src='https://salesiq.zohopublic.in/hasharesstockbrokersltd/clogo/1613986085716_60005626196/photo.ls?nps=202' width='100'>](https://www.mastertrust.co.in/trade-login)| mastertrust | [Master Trust](https://www.mastertrust.co.in/trade-login) | 🟢 |
|[<img src='https://www.motilaloswal.com/img/mologo.png?1210' width='80'>](https://invest.motilaloswal.com/)| motilaloswal | [Motilal Oswal](https://invest.motilaloswal.com/) | 🟢 |
|[<img src='https://jmfl.com/Content/assets/images/logo.png' width='110'>](https://blinktrade.jmfinancialservices.in/userMaster/login)| symphony | [JM Financial](https://blinktrade.jmfinancialservices.in/userMaster/login) | 🟢 |
|[<img src='https://upstox.com/open-demat-account/assets/images/new-oda/oda-logo.svg' width='80'>](https://login.upstox.com/)| upstox | [Upstox](https://login.upstox.com/) | 🟢 |
|[<img src='https://play-lh.googleusercontent.com/EOZ2aJdWEr2xPM29J7Eg7FMIfyPJSRBzXxd1GuCO4ne3qDvDdH-qqcMBEokyH2AQo9k=w240-h480-rw' width='40' height='40'>](https://play.google.com/store/apps/details?id=com.vpcBroker)| vpc | [VPC](https://play.google.com/store/apps/details?id=com.vpcBroker) | 🟢 |
|[<img src='https://zerodha.com/static/images/logo.svg' width='90'>](https://kite.zerodha.com/)| zerodha | [Zerodha](https://kite.zerodha.com/) | 🟢 |


## Usage

To connect to an broker and start trading you need to import an exchange class from fenix library.

To get the full list of ids of supported broker programmatically:


```python
import fenix
print (fenix.brokers)
```

A broker can be used as shown in the examples below:

```python
import fenix

broker = fenix.aliceblue
nfo_tokens = broker.create_nfo_tokens()

# using python eval
id = "angelone"
eq_tokens = eval ('fenix.%s.create_eq_tokens()' % id)

# from variable id
broker_id = 'kotak'
broker_class = getattr(fenix, broker_id)
broker_headers = broker_class.create_headers({
    "user_id": "Your_USER_ID",
    "password": "Your_Password",
    "consumer_key": "Your_Consumer_Key",
    "access_token": "Your_Access_Token",
    })
```

## Paper Testnet Environment

Fenix provides you with a *paper* broker class for testing purposes that allows developers to trade using a virtual broker without having to test their code on to the actual broker. This sandboxed API is a clone of the unified Fenix production API, so, it's literally has the same methods, except for the URL to the broker server which is use to download instrument tokens.

```python
broker = ccxt.paper # SandBox Broker
broker.fetch_orderbook(headers={})
```

## Common Broker Attributes

Every broker has a set of properties and methods.
Here's an overview of generic broker properties with values added for example:

```python
# Market Data Dictonaries

id = 'aliceblue'
indices = {}
eq_tokens = {}
nfo_tokens = {}
token_params = ["user_id", "password", "birth_year", "totpstr", "api_key"]
_session = Broker._create_session()


# Base URLs

base_urls = {
    "api_doc": "https://example.api.com/introduction",
    "token_01": "https://example.api.com/rest/APIService",
    "token_02": "https://example.api.com/",
    "base": "https://example.api.com/rest/api",
    "market_data": "https://example.api.com/contract_master",
}


# Access Token Generation URLs

token_urls = {
    "get_enc_key": f"{base_urls['base']}/getAPIEncpkey",
    "session_id": f"{base_urls['base']}/getUserSID",
    "get_encryption_key": f"{base_urls['token_01']}/getEncryptionKey",
    "enc_key": f"{base_urls['token_02']}/enckey",
    "login": f"{base_urls['token_02']}/validate",
    "verify_totp": f"{base_urls['token_02']}/topt/verify",
}


# Order Placing URLs

urls = {
    "place_order": f"{base_urls['base']}/executePlaceOrder",
    "modify_order": f"{base_urls['base']}/modifyOrder",
    "cancel_order": f"{base_urls['base']}/cancelOrder",
    "exit_bracket_order": f"{base_urls['base']}/exitBracketOrder",
    "orderbook": f"{base_urls['base']}/fetchOrderBook",
    "tradebook": f"{base_urls['base']}/fetchTradeBook",
    "order_history": f"{base_urls['base']}/orderHistory",
    "positions": f"{base_urls['base']}/positionBook",
    "holdings": f"{base_urls['base']}/holdings",
    "sqoff_position": f"{base_urls['base']}/sqrOofPosition",
    "rms_limits": f"{base_urls['base']}/getRmsLimits",
    "profile": f"{base_urls['base']}/accountDetails",
}
```


- `id`: Each broker has an id. The id is not used for anything, it's a string literal for breokr identification purposes. You can differentiate brokers by ids. ids are all lowercase and correspond to broker names.

- `indices`: It is a dictionary used to store all the indices obtained from the broker's Master Script. It contains the indices symbol and token.

- `eq_tokens`: A dicitonary used to manage the data of all the symbols in the Equity Segment along with their token ,tick size, lot size and Exchange.

- `nfo_tokens
`: A dictionary used to store all the data pertaining to the FNO Segment BankNifty, Nifty, FinNifty, MidcapNifty, Sensex to name a few. The data is nested dictionary containing all the data needed for a FNO Symbol like it's Strike Price, Expiry, Option, Trading Symbol, Lot Size, Tick Size and Exchange.

- `token_params`: An array of strings containig all the parameters requre to create the HTTP *headers* used to access endpoints for placing orders, fetching orderbook, positions, etc.

- `_session`: A request session used to send all the reuqests by the broker class.

- `base_urls`: A dictionary containg all the basic endpoints of a broker such as the broker API Documetation URL, marketdata URL, base broker endpoint, etc.

- `token_urls`: A dictionary containing the endpoints required to generate headers.

- `urls`: A dictionary storing all the endpoints related to placing orders, fetching orderbook, positionbook, modify & cancel orders, profile, etc.


## Request Parameters Attributes

These dictationaries convert the Fenix Constants to their respective broker counterparts which are then used to send the API requests to the broker.

- `req_exchange`: Mapping all the Unified Exchange Codes to the broker specific notation.

- `req_order_type`: Mapping all the Unified Order Type Notation to broker's specification.

- `req_product`: Mapping the Order's Product Type provided by the broker to Fenix Notation.

- `req_side`: Maps the Broker's Buy & Sell notation.

- `req_validity`: Mapping Order Validity to Unified fenix notation.

- `req_variety`: Map Order Variety to Unified fenix notation.

```python
req_exchange = {
    ExchangeCode.NSE: "NSE",
    ExchangeCode.NFO: "NFO",
    ExchangeCode.BSE: "BSE",
    ExchangeCode.BFO: "BFO",
    ExchangeCode.BCD: "BCD",
    ExchangeCode.MCX: "MCX",
    ExchangeCode.CDS: "CDS",
}

req_order_type = {
    OrderType.MARKET: "MKT",
    OrderType.LIMIT: "L",
    OrderType.SL: "SL",
    OrderType.SLM: "SL-M"
}

req_product = {
    Product.MIS: "MIS",
    Product.NRML: "NRML",
    Product.CNC: "CNC",
    Product.CO: "CO",
    Product.BO: "BO"
}

req_side = {
    Side.BUY: "BUY",
    Side.SELL: "SELL",
}

req_validity = {
    Validity.DAY: "DAY",
    Validity.IOC: "IOC",
}

req_variety = {
    Variety.REGULAR: "REGULAR",
    Variety.STOPLOSS: "REGULAR",
    Variety.BO: "BO",
    Variety.AMO: "AMO",
}

```

## Response Parameters Attributes

These dictationaries convert the Broker JSON Response data to Fenix Constants counterparts to standardize the JSON response across all brokers.

- `resp_exchange`: Maps Broker Exchange Notation to Unified Fenix Notation.

- `resp_order_type`: Maps Broker Order Type values to Fenix Notation.

- `resp_product`: Used to map an Order's Product type to Unified Fenix Notation.

- `resp_side`: Used to map Order Side to Unified Fenix Notation.

- `resp_segment`: Maps the Segment in which the order is palced to a Unified Fenix Notation

- `resp_validity`: Used to map an Order's Response validity to Unified Fenix Notation.

- `resp_status`: Used to map an Order's current status to Unified Fenix Notation.

```python
resp_order_type = {
    "MKT": OrderType.MARKET,
    "L": OrderType.LIMIT,
    "SL": OrderType.SL,
    "SL-M": OrderType.SLM,
}

resp_segment = {
    "nse_cm": ExchangeCode.NSE,
    "bse_cm": ExchangeCode.BSE,
    "nse_fo": ExchangeCode.NFO,
    "bse_fo": ExchangeCode.BFO,
    "mcx_fo": ExchangeCode.MCX,
    "cde_fo": ExchangeCode.CDS,
    "mcx_sx": ExchangeCode.BFO,
    "bcs_fo": ExchangeCode.BCD,
    "nse_com": ExchangeCode.NCO,
    "bse_com": ExchangeCode.BCO,
}

resp_side = {
    "B": Side.BUY,
    "S": Side.SELL
}

resp_status = {
    "open pending": Status.PENDING,
    "not modified": Status.PENDING,
    "not cancelled": Status.PENDING,
    "modify pending": Status.PENDING,
    "trigger pending": Status.PENDING,
    "cancel pending": Status.PENDING,
    "validation pending": Status.PENDING,
    "put order req received": Status.PENDING,
    "modify validation pending": Status.PENDING,
    "after market order req received": Status.PENDING,
    "modify after market order req received": Status.PENDING,
    "cancelled": Status.CANCELLED,
    "cancelled after market order": Status.CANCELLED,
    "open": Status.OPEN,
    "complete": Status.FILLED,
    "rejected": Status.REJECTED,
    "modified": Status.MODIFIED,
}
```


# Fenix Constants

To standardize JSON Responses across all brokers and to keep all method parameters the same, various Enum classes are used.


The following Enums are used across the fenix library:

- `Side`: Constants representing order sides (BUY, SELL).

- `Root`: Constants representing symbols (BNF, NF, FNF, MIDCPNF).

- `WeeklyExpiry`: Constants representing weekly expiry options (CURRENT, NEXT, FAR, Expiry, LotSize).

- `Option`: Constants representing trading options (CE, PE).

- `OrderType`: Constants representing order types (MARKET, LIMIT, SLM, SL).

- `ExchangeCode`: Constants representing exchange codes (NSE, NFO, BSE, BFO, NCO, BCO, BCD, MCX, CDS).

- `Product`: Constants representing product types (CNC, NRML, MARGIN, MIS, BO, CO, SM).

- `Validity`: Constants representing order validity types (DAY, IOC, GTD, GTC, FOK, TTL).

- `Variety`: Constants representing order variety types (REGULAR, STOPLOSS, AMO, BO, CO, ICEBERG, AUCTION).

- `Status`: Constants representing order status types (PENDING, OPEN, PARTIALLYFILLED, FILLED, REJECTED, CANCELLED, MODIFIED).

- `Order`: Constants representing keys in unified order response dictionaries.

- `Position`: Constants representing keys in unified account positions response dictionaries.

- `Profile`: Constants representing keys in unified account profile response dictionaries.

- `UniqueID`: Constants representing default unique order IDs.


```python
from fenix import constants, aliceblue
from fenix import Side, Order, Option, UniqueID

Side.BUY  # BUY
Side.SELL # SELL

Order.ID # id
Order.AVGPRICE # avgPrice

constants.OrderType.MARKET # MARKET

# prints out all the classes for constants
fenix.constants.__all__

# Using constants during Order Placing.
headers = {
    "ID": "Your_User_Id",
    "AccessToken": "Your_Access_Token",
    "Authorization": f"Bearer  Your_Access_Token",
    "X-SAS-Version": "2.0",
    "User-Agent": "AliceBlue_V21.0.1",
    "Content-Type": "application/json",
    "susertoken": "Your SuserToken",
}

aliceblue.market_order_nfo(option = Option.CE, # CE
                           side = Side.BUY, # BUY
                           unique_id = UniqueID.MARKETORDER, # "MarketOrder"
                           strike_price = 45500,
                           quantity = 15,
                           headers = headers,
                           )
```

# Loading Broker Master Scripts

In most cases you are required to load the data of trading symbols for a particular broker prior to accessing other API methods. If you forget to load the symbol data the fenix library will do that automatically upon your first call to the unified API. It will send two HTTP requests, first for symbols and then the second one for other data, sequentially. For that reason, your first call to a unified Fenix API method like create_order, create_nfo_order, create_bo_order, etc. will take more time, than the consequent calls, since it has to do more work loading the market information from the Broker API.

In order to load trading symbol data manually beforehand call the `create_nfo_tokens ()` / `create_eq_tokens ()` method on a broker class. It returns a dictionary of markets indexed by trading symbol/expiry. If you want more control over the execution of your logic, preloading markets by hand is recommended.

The broker MasterScript data is formatted into a standarized way and stored in the following class variables:

## cls.eq_tokens

This class variable stores the trading symbols from both *NSE & BSE* exchanges. The data is formatted in the following form:

```python
#     Exchange
#     ↓
#     ↓        Ticker of Script Similar to TradingView
#     ↓        ↓
#     ↓        ↓        Script Data
#     ↓        ↓        ↓
#     ↓        ↓        ↓
#     ↓        ↓        ↓
#     ↓        ↓        ↓
#     ↓        ↓        ↓
#     ↓        ↓        ↓
{
    "NSE":{ "SAIL": {"Symbol": "SAIL-EQ",
                        "Token": 2963,
                        "LotSize": 1,
                        "TickSize": 0.05,
                        "Exchange": "NSE"
                    },

        "AARTIIND": {"Symbol": "AARTIIND-EQ",
                        "Token": 7,
                        "LotSize": 1,
                        "TickSize": 0.05,
                        "Exchange": "NSE"
                    },

        "RELIANCE": {"Symbol": "RELIANCE-EQ",
                        "Token": 2885,
                        "LotSize": 1,
                        "TickSize": 0.05,
                        "Exchange": "NSE"
                    },
        ...
        },

    "BSE":{ "ONGC": {"Symbol": "ONGC",
                        "Token": 500312,
                        "TickSize": 0.05,
                        "LotSize": 1,
                        "Exchange": "BSE"
                    },

            "JSWSTEEL": {"Symbol": "JSWSTEEL",
                            "Token": 500228,
                            "TickSize": 0.05,
                            "LotSize": 1,
                            "Exchange": "BSE"
                        },

            "RELIANCE": {"Symbol": "RELIANCE",
                            "Token": 500325,
                            "TickSize": 0.05,
                            "LotSize": 1,
                            "Exchange": "BSE"
                        },
        ...
        }
}
```

## cls.indices

This dictionary stores the Indices data from both *NSE & BSE* exchanges and is formatted in the following way:

```python
#      Ticker of Index Similar to TradingView
#      ↓
#      ↓        Index Data
#      ↓        ↓
#      ↓        ↓
#      ↓        ↓
#      ↓        ↓
#      ↓        ↓
#      ↓        ↓
{
    "NIFTY": {"Symbol": "NIFTY 50", "Token": "26000"},
    "NIFTY 500": {"Symbol": "NIFTY 500", "Token": "26004"},
    "NIFTY AUTO": {"Symbol": "NIFTY AUTO", "Token": "26029"},
    "BANKNIFTY": {"Symbol": "NIFTY BANK", "Token": "26009"},
    "FINNIFTY": {"Symbol": "NIFTY FIN SERVICE", "Token": "26037"},
    "MIDCPNIFTY": {"Symbol": "NIFTY MIDCAP SELECT", "Token": "26074"},
}
```

## cls.nfo_tokens

This class variable is a dictionary sotring the data for the FNO segment in the following format:

```python
#      Weekly Expiry: CURRENT, NEXT, FAR, Expiry (Expiry Dates), LotSize
#      ↓
#      ↓          Segment: BANKNIFTY, NIFTY, FININIFTY, MIDCPNIFTY, SENSEX
#      ↓          ↓
#      ↓          ↓           Option: CE, PE
#      ↓          ↓           ↓
#      ↓          ↓           ↓        Strike Price: 38500, 39000, ...
#      ↓          ↓           ↓        ↓
#      ↓          ↓           ↓        ↓          Script Data
#      ↓          ↓           ↓        ↓          ↓
#      ↓          ↓           ↓        ↓          ↓
#      ↓          ↓           ↓        ↓          ↓
#      ↓          ↓           ↓        ↓          ↓
#      ↓          ↓           ↓        ↓          ↓
{
    "CURRENT": {"BANKNIFTY": {
                            "CE": {
                                    "38500": {
                                                "Token": 40589,
                                                "Symbol": "BANKNIFTY20MAR24C38500",
                                                "Expiry": "2024-03-20",
                                                "Option": "CE",
                                                "StrikePrice": "38500",
                                                "LotSize": 15,
                                                "Root": "BANKNIFTY",
                                                "TickSize": 0.05,
                                                "Exchange": "NFO",
                                                "ExpiryName": "CURRENT"
                                            },
                                    "39000": {
                                                "Token": 40642,
                                                "Symbol": "BANKNIFTY20MAR24C39000",
                                                "Expiry": "2024-03-20",
                                                "Option": "CE",
                                                "StrikePrice": "39000",
                                                "LotSize": 15,
                                                "Root": "BANKNIFTY",
                                                "TickSize": 0.05,
                                                "Exchange": "NFO",
                                                "ExpiryName": "CURRENT"
                                            }
                            },
                            "PE": {
                                    "38500": {
                                            "Token": 40592,
                                            "Symbol": "BANKNIFTY20MAR24P38500",
                                            "Expiry": "2024-03-20",
                                            "Option": "PE",
                                            "StrikePrice": "38500",
                                            "LotSize": 15,
                                            "Root": "BANKNIFTY",
                                            "TickSize": 0.05,
                                            "Exchange": "NFO",
                                            "ExpiryName": "CURRENT"
                                    },
                                    "39000": {
                                            "Token": 40645,
                                            "Symbol": "BANKNIFTY20MAR24P39000",
                                            "Expiry": "2024-03-20",
                                            "Option": "PE",
                                            "StrikePrice": "39000",
                                            "LotSize": 15,
                                            "Root": "BANKNIFTY",
                                            "TickSize": 0.05,
                                            "Exchange": "NFO",
                                            "ExpiryName": "CURRENT"
                                        }+
                            }
                        },
                "NIFTY": {...},
                "FINNIFTY": {...},
                "MIDCPNIFTY": {...},
                "SENSEX": {...}
                },
    "NEXT": {...},
    "FAR": {...},
    "Expiry": {
        "BANKNIFTY": ["2024-03-20", ...],
        "NIFTY": ["2024-03-21", ...],
        "FINNIFTY": ["2024-03-19", ...],
        "MIDCPNIFTY": ["2024-03-18", ...],
        "SENSEX": ["2024-03-18", ...],
        },
    "LotSize": {
        "BANKNIFTY": 15,
        "NIFTY": 50,
        "FINNIFTY": 40,
        "MIDCPNIFTY": 75,
        "SENSEX": 10
    }
}
```


# API Methods / Endpoints

Each broker offers a set of API methods. Each method of the API is called an *endpoint*. Endpoints are HTTP URLs for querying various types of information. All endpoints return JSON in response to client requests.

Usually, there is an endpoint for retrieving an order book, an endpoint for retrieving trade history, endpoints for placing and canceling orders, etc... Basically every kind of action you could perform within a particular broker has a separate endpoint URL offered by the API.

Because the set of methods differs from broker to broker, the fenix library implements a unified API supporting a subset of common methods.

The following are the unified Methods / Endpoints provided by Fenix library:

## Market Data Methods

These methods download the MasterScript of the broker and stores the data of the Script in the form of a dictionary storing the following values: `Symbol`, `Token`, `LotSize`, `TickSize`, `Exchange`, `Expiry`, `Strike Price`, etc...

- `create_eq_tokens ()`: Fetches all the Equity market Scripts and stores the data in the `eq_tokens` attribute of the broker.

- `create_indices ()`: Fetches all the Indices data. Stores the data in the `indices` attribute of the broker.

- `create_nfo_tokens ()`: Fetches all the FNO Segment data. Stores the data in the `nfo_tokens` attribute of the broker.


## Headers Method

The `create_headers (params: dict)` method takes the user's credentials of the respective broker in the form of a dictionary. The keys of the `params` dictionary can be found by using the `tokens_params` attribute.


## Order Placing Methods

The methods which have the following name `create_order_*** ()` are used to place any type of order in the respective segments:

### create_order_nfo ()
This method allows the user to place any type of order in the FNO Segment. It takes the following parameters:

- `exchange` (str): Exchange to place the order in. [ExchangeCode.NFO]

- `root` (str): Derivative: BANKNIFTY, NIFTY, etc...

- `expiry` (str): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'.

- `option` (str): Option Type: 'CE', 'PE'.

- `strike_price` (int): Strike Price of the Option.

- `quantity` (int): Order quantity.

- `side` (str): Order Side: 'BUY', 'SELL'.

- `product` (str): Order product.

- `validity` (str): Order validity.

- `variety` (str): Order variety.

- `unique_id` (str): Unique user orderid

- `headers` (dict): headers to send order request with.

- `price` (float, optional): price of the order. Defaults to 0.

- `trigger` (float, optional): trigger price of the order. Defaults to 0.


```python
finvasia.create_order_nfo(exchange = constants.ExchangeCode.NFO,
                         root = constants.Root.BNF,
                         expiry = constants.WeeklyExpiry.CURRENT,
                         option = "CE",
                         strike_price = '45500',
                         quantity = 15,
                         side = "BUY",
                         product = constants.Product.MIS,
                         validity = constants.Validity.DAY,
                         variety = constants.Variety.REGULAR,
                         unique_id = 'CREATEOrderNFO',
                         headers = {}, # Add your headers dict.
                         price = 13.0,
                         trigger = 12.0
                         )
```

### create_order_eq ( )
This method allows the user to place any type of order in the Equity Segment. It takes the following parameters:

- `exchange` (str): Exchange to place the order in. Possible Values: NSE, BSE.

- `symbol` (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL".

- `quantity` (int): Order quantity.

- `side` (str): Order Side: BUY, SELL.

- `product` (str, optional): Order product.

- `validity` (str, optional): Order validity.

- `variety` (str, optional): Order variety.

- `unique_id` (str): Unique user order_id.

- `headers` (dict): headers to send order request with.

- `price` (float): Order price.

- `trigger` (float): order trigger price.

- `target` (float, optional): Order Target price. Defaults to 0.

- `stoploss` (float, optional): Order Stoploss price. Defaults to 0.

- `trailing_sl` (float, optional): Order Trailing Stoploss percent. Defaults to 0.

```python
angelone.create_order_eq(exchange = constants.ExchangeCode.NSE,
                         symbol = "RELIANCE",
                         quantity = 10,
                         side = "SELL",
                         product = constants.Product.MIS,
                         validity = constants.Validity.DAY,
                         variety = constants.Variety.REGULAR,
                         unique_id = "NSEOrder",
                         headers = {},
                         price = 2840.0,
                         trigger = 2845.0
                         )
```

### create_order_bo ( )

This method allows the user to place Bracket Orders in the supported broker. It takes the following parameters:

- `token` (int): Exchange token.

- `exchange` (str): Exchange to place the order in.

- `symbol` (str): Trading symbol.

- `price` (float): Order price

- `trigger` (float): order trigger price

- `quantity` (int): Order quantity.

- `side` (str): Order Side: BUY, SELL.

- `unique_id` (str): Unique user order_id.

- `headers` (dict): headers to send order request with.

- `target` (float, optional): Order Target price. Defaults to 0.

- `stoploss` (float, optional): Order Stoploss price. Defaults to 0.

- `trailing_sl` (float, optional): Order Trailing Stoploss percent. Defaults to 0.

- `product` (str, optional): Order product.

- `validity` (str, optional): Order validity.

- `variety` (str, optional): Order variety.

```python
symphony.create_order_bo(token=42163,
                         exchange = constants.ExchangeCode.NFO,
                         symbol = "BANKNIFTY22NOV23C45500",
                         price = 10,
                         trigger = 9,
                         quantity = 15,
                         side = constants.Side.BUY,
                         unique_id ="CreateOrderBO",
                         headers = {},
                         target = 12,
                         stoploss = 5,
                         trailing_sl = 3,
                         product = constants.Product.MIS,
                         validity = constants.Validity.DAY,
                         variety = constants.Variety.REGULAR
                         )
```

### create_order ( )
This method allows the user to place orders in any segment. It takes the following parameters:

- `token` (int): Exchange token.
- `exchange` (str): Exchange to place the order in.
- `symbol` (str): Trading symbol.
- `quantity` (int): Order quantity.
- `side` (str): Order Side: BUY, SELL.
- `product` (str, optional): Order product.
- `validity` (str, optional): Order validity.
- `variety` (str, optional): Order variety.
- `unique_id` (str): Unique user order_id.
- `headers` (dict): headers to send order request with.
- `price` (float, optional): Order price. Defaults to 0.
- `trigger` (float, optional): order trigger price. Defaults to 0.
- `target` (float, optional): Order Target price. Defaults to 0.
- `stoploss` (float, optional): Order Stoploss price. Defaults to 0.
- `trailing_sl` (float, optional): Order Trailing Stoploss percent. Defaults to 0.

```python
symphony.create_order(token=42163,
                        exchange = constants.ExchangeCode.NFO,
                        symbol = "BANKNIFTY22NOV23C45500",
                        quantity = 15,
                        side = "BUY",
                        product = constants.Product.MIS,
                        validity = constants.Validity.DAY,
                        variety = constants.Variety.REGULAR,
                        unique_id = 'CreateOrder',
                        headers = {},
                        price = 10.25,
                        trigger = 9.25
                        )

```