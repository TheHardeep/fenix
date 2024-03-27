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
nfo_tokens = broker.create_fno_tokens()

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

In order to load trading symbol data manually beforehand call the `create_fno_tokens ()` / `create_eq_tokens ()` method on a broker class. It returns a dictionary of markets indexed by trading symbol/expiry. If you want more control over the execution of your logic, preloading markets by hand is recommended.

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
    ...
}
```

## cls.nfo_tokens

This class variable is a dictionary sotring the data for the FNO segment in the following format:

```python
#      Weekly Expiry: CURRENT, NEXT, FAR, Expiry (Expiry Dates), LotSize
#      ↓
#      ↓          Segment: BANKNIFTY, NIFTY, FININIFTY, MIDCPNIFTY, SENSEX, BANKEX
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
                "SENSEX": {...},
                "BANKEX": {...}
                },
    "NEXT": {...},
    "FAR": {...},
    "Expiry": {
        "BANKNIFTY": ["2024-03-20", ...],
        "NIFTY": ["2024-03-21", ...],
        "FINNIFTY": ["2024-03-19", ...],
        "MIDCPNIFTY": ["2024-03-18", ...],
        "SENSEX": ["2024-03-18", ...],
        "BANKEX": ["2024-03-19", ...],
        },
    "LotSize": {
        "BANKNIFTY": 15,
        "NIFTY": 50,
        "FINNIFTY": 40,
        "MIDCPNIFTY": 75,
        "SENSEX": 10,
        "BANKEX": 15
    }
}
```


# API Methods / Endpoints

Each broker offers a set of API methods. Each method of the API is called an *endpoint*. Endpoints are HTTP URLs for querying various types of information. All endpoints return JSON in response to client requests.

Usually, there is an endpoint for retrieving an order book, an endpoint for retrieving trade history, endpoints for placing and canceling orders, etc... Basically every kind of action you could perform within a particular broker has a separate endpoint URL offered by the API.

Because the set of methods differs from broker to broker, the fenix library implements a unified API supporting a subset of common methods.

The following are the unified Methods / Endpoints provided by Fenix library:

## Token Data Methods

These methods download the MasterScript of the broker and stores the data of the Script in the form of a dictionary storing the following values: `Symbol`, `Token`, `LotSize`, `TickSize`, `Exchange`, `Expiry`, `Strike Price`, etc...

- `create_eq_tokens ()`: Fetches all the Equity market Scripts and stores the data in the `eq_tokens` attribute of the broker.

- `create_indices ()`: Fetches all the Indices data. Stores the data in the `indices` attribute of the broker.

- `create_fno_tokens ()`: Fetches all the FNO Segment data. Stores the data in the `nfo_tokens` attribute of the broker.


## Headers Method

The `create_headers (params: dict)` method takes the user's credentials of the respective broker in the form of a dictionary. The keys of the `params` dictionary can be found by using the `tokens_params` attribute.

The output of the function will giver a dictionary which will ahve the headers as well as other data used to make requests to the broker.

```python
params = {
    "user_id": "YOUR_USER_ID"
    "password": "YOUR_PASSWORD"
    "birth_year": "YOUR_BIRTH_YEAR"
    "totpstr": "YOUR_TOTP_STRING"
    "api_key": "YOUR_API_KEY"
    }

headers = aliceblue.create_headers(params)
```

### Sample Header Structure
```python
# AliceBlue Headers
{
"headers":
    {
        "ID": "YOUR_USER_ID",
        "AccessToken": "GENERATED_ACCESS_TOKEN",
        "Authorization": f'Bearer YPIR_USER_ID GENERATED_ACCESS_TOKEN',
        "X-SAS-Version": "2.0",
        "User-Agent": "AliceBlue_V21.0.1",
        "Content-Type": "application/json",
        "susertoken": "GENERATED_SUSERTOKEN"
    }
}
```

## Generalized Order Placing Methods

The methods which have the following name `create_order_* ()` are used to place any type of order in the respective segments:


Common Function Parameters across all create_order_* ():


- `quantity` (int): Order quantity.

- `side` (str): Order Side: BUY, SELL.

- `unique_id` (str): Unique user order_id.

- `headers` (dict): headers to send order request with.

- `product` (str, optional): Order product. Defaults to Product.MIS.

- `validity` (str, optional): Order validity. Defaults to Validity.DAY.

- `variety` (str, optional): Order variety Defaults to Variety.REGULAR.

- `price` (float, optional): price of the order. Defaults to 0.

- `trigger` (float, optional): trigger price of the order. Defaults to 0.

All the order funcitnos in the Fenix Library including the `modify_order ( )` as well as `cancel_order ( )` return a dictionary with the same keys as mentioned in the [OrderBook Structure](#orderbook--tradebook-structure).

### create_order_fno ( )
This method allows the user to place any type of order in the FNO Segment. It takes the following parameters:

- `exchange` (str): Exchange to place the order in.

- `root` (str): Derivative: BANKNIFTY, NIFTY, etc...

- `expiry` (str): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'.

- `option` (str): Option Type: 'CE', 'PE'.

- `strike_price` (int): Strike Price of the Option.


    ```python
    finvasia.create_order_fno(exchange = constants.ExchangeCode.NFO,
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

### create_order ( )
This method allows the user to place orders in any segment. It takes the following parameters:

- `token_dict` (dict): a dictionary with details of the Ticker. Obtianed from eq_tokens or nfo_tokens. (Contains "Exchange", "Token" and "Symbol" as keys.)

- `target` (float, optional): Order Target price. Defaults to 0.

- `stoploss` (float, optional): Order Stoploss price. Defaults to 0.

- `trailing_sl` (float, optional): Order Trailing Stoploss percent. Defaults to 0.

    ```python
    headers = symphony.create_headers(params)
    token_data = symphony.nfo_tokens["CURRENT"]["BANKNIFTY"]["CE"]["38500"]

    symphony.create_order(token_dict = token_data,
                          quantity = 15,
                          side = "BUY",
                          product = constants.Product.MIS,
                          validity = constants.Validity.DAY,
                          variety = constants.Variety.REGULAR,
                          unique_id = 'CreateOrder',
                          headers = headers,
                          price = 10.25,
                          trigger = 9.25,
                          target = 12.50,
                          stoploss = 7.25,
                          trailing_sl = 4.50,
                          )
    ```

## OrderType Specific Order Placing Methods

There are 4 types of different methods based on the Market, Limit, Stoploss & Stoploss-Market OrderTypes.

They are also seperated by the Segments. For F&O and Equity Segments both contian these type of methods as well as Generalized methods which work the same as create_order_*( ) but for the above mentioned OrderTypes.

### Common Method Parameters:

Common Parameters across all order types:

- `quantity` (int): Order quantity.

- `side` (str): Order Side: BUY, SELL.

- `unique_id` (str): Unique user order_id.

- `headers` (dict): headers to send order request with.

- `product` (str, optional): Order product. Defaults to Product.MIS.

- `validity` (str, optional): Order validity. Defaults to Validity.DAY.

- `variety` (str, optional): Order variety Defaults to Variety.REGULAR.


### Market Order

A market order does not require a *price* or *trigger* to send the order.

#### Equity Segment

- `exchange` (str): Exchange to place the order in. Possible Values: NSE, BSE.

- `symbol` (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"


    ```python
    upstox.market_order_eq(exchange = ExchangeCode.NSE,
                           symbol = "RELIANCE",
                           quantity =  10,
                           side = "BUY",
                           unique_id = "MarketOrderEQ",
                           headers = headers
                           )
    ```

#### F&O Segment

- `option` (str): Option Type: 'CE', 'PE'.

- `strike_price` (str): Strike Price of the Option.

- `root` (str): Derivative: BANKNIFTY, NIFTY, FINNIFTY, MIDCPNIFTY, SENSEX, BANKEX.

- `expiry` (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.

- `exchange` (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.


    ```python
    kotakneo.market_order_fno(option = "CE",
                              strike_price = "45500",
                              quantity = 15,
                              side = "BUY",
                              unique_id = 'MARKETOrderNFO',
                              headers = headers,
                              )
    ```

#### Any Segment

- `token_dict` (dict): a dictionary with details of the Ticker. Obtianed from eq_tokens or nfo_tokens. (Contains "Exchange", "Token" and "Symbol" as keys.)

    ```python
    from fenix import Side, fyers

    token_data = symphony.nfo_tokens["CURRENT"]["NIFTY"]["PE"]["22100"]

    fyers.market_order(token_dict = token_data,
                       quantity = 100,
                       side = Side.SELL,
                       unique_id = 'MarketOrder',
                       headers = headers
                       )
    ```


### Limit Order

Limit Orders require another parameter along with other [common parameters](#common-method-parameters) discussed before:

- `price` (float): Order price.

#### Equity Segment

- `exchange` (str): Exchange to place the order in. Possible Values: NSE, BSE.

- `symbol` (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"


    ```python
    upstox.limit_order_eq(exchange = ExchangeCode.NSE,
                          symbol = "RELIANCE",
                          price = 2890,
                          quantity =  10,
                          side = "BUY",
                          unique_id = "MarketOrderEQ",
                          headers = headers
                          )
    ```

#### F&O Segment

- `option` (str): Option Type: 'CE', 'PE'.

- `strike_price` (str): Strike Price of the Option.

- `root` (str): Derivative: BANKNIFTY, NIFTY, FINNIFTY, MIDCPNIFTY, SENSEX, BANKEX.

- `expiry` (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.

- `exchange` (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.


    ```python
    kotakneo.limit_order_fno(option = "CE",
                             strike_price = "45500",
                             price = 250.50,
                             quantity = 15,
                             side = "BUY",
                             unique_id = 'MARKETOrderNFO',
                             headers = headers,
                             )
    ```

#### Any Segment

- `token_dict` (dict): a dictionary with details of the Ticker. Obtianed from eq_tokens or nfo_tokens. (Contains "Exchange", "Token" and "Symbol" as keys.)

    ```python
    from fenix import Side, fyers

    token_data = symphony.nfo_tokens["CURRENT"]["NIFTY"]["PE"]["22100"]

    fyers.limit_order(token_dict = token_data,
                      price = 400.50,
                      quantity = 100,
                      side = Side.SELL,
                      unique_id = 'MarketOrder',
                      headers = headers
                      )
    ```


### Stoploss Order

Stoploss Orders require another parameter along with other [common parameters](#common-method-parameters) discussed before:

- `price` (float): Order price.

- `trigger` (float): order trigger price

#### Equity Segment

- `exchange` (str): Exchange to place the order in. Possible Values: NSE, BSE.

- `symbol` (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"


    ```python
    upstox.sl_order_eq(exchange = ExchangeCode.NSE,
                       symbol = "RELIANCE",
                       price = 2890,
                       trigger = 2885,
                       quantity =  10,
                       side = "BUY",
                       unique_id = "MarketOrderEQ",
                       headers = headers
                       )
    ```

#### F&O Segment

- `option` (str): Option Type: 'CE', 'PE'.

- `strike_price` (str): Strike Price of the Option.

- `root` (str): Derivative: BANKNIFTY, NIFTY, FINNIFTY, MIDCPNIFTY, SENSEX, BANKEX.

- `expiry` (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.

- `exchange` (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.


    ```python
    kotakneo.sl_order_fno(option = "CE",
                          strike_price = "45500",
                          price = 250.50,
                          trigger = 243.0,
                          quantity = 15,
                          side = "BUY",
                          unique_id = 'MARKETOrderNFO',
                          headers = headers,
                          )
    ```

#### Any Segment

- `token_dict` (dict): a dictionary with details of the Ticker. Obtianed from eq_tokens or nfo_tokens. (Contains "Exchange", "Token" and "Symbol" as keys.)

    ```python
    from fenix import Side, fyers

    token_data = symphony.nfo_tokens["CURRENT"]["NIFTY"]["PE"]["22100"]

    fyers.sl_order(token_dict = token_data,
                   price = 400.50,
                   trigger = 395.0,
                   quantity = 100,
                   side = Side.SELL,
                   unique_id = 'MarketOrder',
                   headers = headers
                   )
    ```



### Stoploss-Market Order

Stoploss-Market Orders require another parameter along with other [common parameters](#common-method-parameters) discussed before:

- `trigger` (float): order trigger price

#### Equity Segment

- `exchange` (str): Exchange to place the order in. Possible Values: NSE, BSE.

- `symbol` (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"


    ```python
    upstox.slm_order_eq(exchange = ExchangeCode.NSE,
                       symbol = "RELIANCE",
                       trigger = 2885,
                       quantity =  10,
                       side = "BUY",
                       unique_id = "MarketOrderEQ",
                       headers = headers
                       )
    ```

#### F&O Segment

- `option` (str): Option Type: 'CE', 'PE'.

- `strike_price` (str): Strike Price of the Option.

- `root` (str): Derivative: BANKNIFTY, NIFTY, FINNIFTY, MIDCPNIFTY, SENSEX, BANKEX.

- `expiry` (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.

- `exchange` (str, optional):  Exchange to place the order in. Defaults to ExchangeCode.NFO.


    ```python
    kotakneo.slm_order_fno(option = "CE",
                          strike_price = "45500",
                          trigger = 243.0,
                          quantity = 15,
                          side = "BUY",
                          unique_id = 'MARKETOrderNFO',
                          headers = headers,
                          )
    ```

#### Any Segment

- `token_dict` (dict): a dictionary with details of the Ticker. Obtianed from eq_tokens or nfo_tokens. (Contains "Exchange", "Token" and "Symbol" as keys.)

    ```python
    from fenix import Side, fyers

    token_data = symphony.nfo_tokens["CURRENT"]["NIFTY"]["PE"]["22100"]

    fyers.slm_order(token_dict = token_data,
                   trigger = 395.0,
                   quantity = 100,
                   side = Side.SELL,
                   unique_id = 'MarketOrder',
                   headers = headers
                   )
    ```

## Modify Order

This method is used to modufy an open order and requires the following parameters:

- `order_id` (str): id of the order to modify.

- `price` (float, optional): price of the order. Defaults to None.

- `trigger` (float, optional): trigger price of the order. Defaults to None.

- `quantity` (int, optional): order quantity. Defaults to None.

- `order_type` (str, optional): Type of Order. defaults to None.

- `validity` (str, optional): Order validity Defaults to None.

- `headers` (dict): headers to send modify_order request with.


    ```python
    motilaloswal.modify_order(order_id = '231217000002374',
                            price = 10.0,
                            trigger = 9.5,
                            quantity = 15,
                            order_type = constants.OrderType.SL,
                            validity = constants.Validity.DAY,
                            headers = headers
                            )
    ```


## Cancel Order

This method is used to cancel an open order. It requires the follwoing parameters:

- `order_id` (str): id of the order.

- `headers` (dict): headers to send cancel_order request with.

    ```python
    angelone.cancel_order(order_id = '231217000005603',
                        headers=headers
                        )
    ```

## OrderBook / TradeBook Methods

### OrderBook Methods

There are 2 types of orderbook methods:

1. `fetch_orderbook ()`: This method fetches the orderbook form the broker and converts each order detail into Unified Fenix Order Format.

2. `fetch_orders ()`: Sometimes the data in the orderbook of a broker does not include the average price of the order if the order has been filled, to provide the average price of such orders a request for the tradebook is made form where these prices are fetched.

Paramter:
 - `headers` (dict): headers to send orderbook request with.

```python
orders = zerodha.fetch_orders(headers)
```

### TradeBook Method

The `fetch_tradebook ()`  fetches the broker tradebook and ocnverts the data in Unified Fenix JSON Format.

Paramters:
 - `headers` (dict): headers to send tradebook request with.

```python
orders = zerodha.fetch_tradebook(headers)
```

### OrderBook / TradeBook Structure

```python
[{
    'id': '231124401406418',
    'userOrderId': 'MARKETOrderNFO',
    'timestamp': datetime.datetime(2023, 11, 24, 12, 51, 30),
    'symbol': 'BANKNIFTY23NOV43700CE',
    'token': 14918402,
    'side': 'BUY',
    'type': 'MARKET',
    'avgPrice': 256.8,
    'price': 0,
    'triggerPrice': 0,
    'quantity': 15,
    'filled': 15,
    'remaining': 0,
    'cancelleldQty': 0,
    'status': 'COMPLETE',
    'rejectReason': None,
    'disclosedQuantity': 0,
    'product': 'MIS',
    'exchange': 'NFO',
    'segment': 'NFO',
    'validity': 'DAY',
    'variety': 'REGULAR',
    'info': {}
    },
    ...
]
```
An OrderBook / TradeBook is an array of dictionaries with the following keys:

- `id`: Order ID

- `userOrderId`: ID provided by the user at the time of order placement.

- `timestamp`: datetime object of the order Execution Time.

- `symbol`: Symbol of the Ticker for which the order is placed.

- `token`: Token of the Ticker.

- `side`: Buy / Sell Side of the Order.

- `type`: Order Type.

- `avgPrice`: Executed Average Price of the Order.

- `price`: Price at which the order is placed.

- `triggerPrice`: Trigger Price for the Order.

- `quantity`: Quantity of the Order.

- `filled`: Qauntity of the order which has executed.

- `remaining`: Unfilled quantity of the order.

- `cancelleldQty`: If the Order is cancelled, then the remaining Quantity is mentinoed here.

- `status`: Status of the Order.

- `rejectReason`: Reason for Order Rejection.

- `disclosedQuantity`: Disclosed Quantity.

- `product`: Product of the Order. Ex: MIS, NRML, etc.

- `exchange`: Exchange in which order is palced.

- `segment`: Segment of the Exchange where order is placed.

- `validity`: Order Validity. Ex: Day, IOC, etc..

- `variety`: Order Variety. Ex: REGULAR, STOPLOSS, BO, etc.

- `info`: A dictionary with the original broker json for the order.

## Order & Order History Method

1.  `fetch_order ()`: This method is used to fetch the current detail of an order.

2. `fetch_orderhistory ()`: This method is used to fetch the history of an order.

**Parameters:**

- `order_id` (str): id of the order.
- `headers` (dict): headers to send the request with.

### Order Structure

```python
{
    'id': '231122000383315',
    'userOrderId': 'SLOrderNFO',
    'timestamp': datetime.datetime(2023, 11, 22, 11, 9, 37),
    'symbol': 'BANKNIFTY22NOV2345500CE',
    'token': '42163',
    'side': 'BUY',
    'type': 'SL',
    'avgPrice': 0.0,
    'price': 240.0,
    'triggerPrice': 235.0,
    'targetPrice': 0.0,
    'stoplossPrice': 0.0,
    'trailingStoploss': 0.0,
    'quantity': 15,
    'filled': 0,
    'remaining': 15,
    'cancelleldQty': 0,
    'status': 'REJECTED',
    'rejectReason': 'Admin stopped AMO',
    'disclosedQuantity': 0,
    'product': 'MIS',
    'exchange': 'NFO',
    'segment': 'NFO',
    'validity': 'DAY',
    'variety': 'AMO',
    'info': {
        'variety': 'AMO',
        'ordertype': 'STOPLOSS_LIMIT',
        'producttype': 'INTRADAY',
        'duration': 'DAY',
        'price': 240.0,
        'triggerprice': 235.0,
        'quantity': '15',
        'disclosedquantity': '0',
        'squareoff': 0.0,
        'stoploss': 0.0,
        'trailingstoploss': 0.0,
        'tradingsymbol': 'BANKNIFTY22NOV2345500CE',
        'transactiontype': 'BUY',
        'exchange': 'NFO',
        'symboltoken': '42163',
        'ordertag': 'SLOrderNFO',
        'instrumenttype': 'OPTIDX',
        'strikeprice': 45500.0,
        'optiontype': 'CE',
        'expirydate': '22NOV2023',
        'lotsize': '15',
        'cancelsize': '0',
        'averageprice': 0.0,
        'filledshares': '0',
        'unfilledshares': '15',
        'orderid': '231122000383315',
        'text': 'Admin stopped AMO',
        'status': 'rejected',
        'orderstatus': '',
        'updatetime': '22-Nov-2023 11:09:37',
        'exchtime': '',
        'exchorderupdatetime': '',
        'fillid': '',
        'filltime': '',
        'parentorderid': '',
        'uniqueorderid': '231122000383315'
        }
    }
```

### Order History Structure

```python
[{'id': '231217000002374',
  'userOrderId': '1702818893-475934-HBWPK2428E-ADMINAPI',
  'timestamp': datetime.datetime(2023, 12, 17, 18, 44, 53),
  'symbol': 'BANKNIFTY23D2047500CE',
  'token': '38223',
  'side': 'BUY',
  'type': 'SL',
  'avgPrice': 0.0,
  'price': 10.0,
  'triggerPrice': 0.0,
  'targetPrice': 0.0,
  'stoplossPrice': 0.0,
  'trailingStoploss': 0.0,
  'quantity': 15,
  'filled': 0,
  'remaining': 15,
  'cancelleldQty': 0,
  'status': 'CANCELLED',
  'rejectReason': '--',
  'disclosedQuantity': 0,
  'product': 'MIS',
  'exchange': 'NFO',
  'segment': 'NFO',
  'validity': 'DAY',
  'variety': '',
  'info': {}},
 {'id': '231217000002374',
  'userOrderId': '1702818723-649114-HBWPK2428E-ADMINAPI',
  'timestamp': datetime.datetime(2023, 12, 17, 18, 42, 3),
  'symbol': 'BANKNIFTY23D2047500CE',
  'token': '38223',
  'side': 'BUY',
  'type': 'SL',
  'avgPrice': 0.0,
  'price': 10.0,
  'triggerPrice': 9.5,
  'targetPrice': 0.0,
  'stoplossPrice': 0.0,
  'trailingStoploss': 0.0,
  'quantity': 15,
  'filled': 0,
  'remaining': 15,
  'cancelleldQty': 0,
  'status': 'PENDING',
  'rejectReason': '--',
  'disclosedQuantity': 0,
  'product': 'MIS',
  'exchange': 'NFO',
  'segment': 'NFO',
  'validity': 'DAY',
  'variety': '',
  'info': {}},
 {'id': '231217000002374',
  'userOrderId': '1702818612-325437-HBWPK2428E-ADMINAPI',
  'timestamp': datetime.datetime(2023, 12, 17, 18, 40, 12),
  'symbol': 'BANKNIFTY23D2047500CE',
  'token': '38223',
  'side': 'BUY',
  'type': 'SL',
  'avgPrice': 0.0,
  'price': 11.0,
  'triggerPrice': 10.5,
  'targetPrice': 0.0,
  'stoplossPrice': 0.0,
  'trailingStoploss': 0.0,
  'quantity': 30,
  'filled': 0,
  'remaining': 30,
  'cancelleldQty': 0,
  'status': 'PENDING',
  'rejectReason': '--',
  'disclosedQuantity': 0,
  'product': 'MIS',
  'exchange': 'NFO',
  'segment': 'NFO',
  'validity': 'DAY',
  'variety': '',
  'info': {}},
 {'id': '231217000002374',
  'userOrderId': '1702798953-865415-HBWPK2428E-ADMINAPI',
  'timestamp': datetime.datetime(2023, 12, 17, 13, 12, 33),
  'symbol': 'BANKNIFTY23D2047500CE',
  'token': '38223',
  'side': 'BUY',
  'type': 'SL',
  'avgPrice': 0.0,
  'price': 10.0,
  'triggerPrice': 9.0,
  'targetPrice': 0.0,
  'stoplossPrice': 0.0,
  'trailingStoploss': 0.0,
  'quantity': 15,
  'filled': 0,
  'remaining': 15,
  'cancelleldQty': 0,
  'status': 'PENDING',
  'rejectReason': '--',
  'disclosedQuantity': 0,
  'product': 'MIS',
  'exchange': 'NFO',
  'segment': 'NFO',
  'validity': 'DAY',
  'variety': '',
  'info': {}}]
```


## PositionBook / Holdings Methods

There are 3 methods for finding positions:

### PostionBook Methods

1. `fetch_day_positions ()`: This method is used to fetch the Day's Account Positions.

2. `fetch_net_positions ()`: This method fetches the Net Positions of an an Account meaning all the previouis positions that the user may have in their account.

3. `fetch_positions ()`: This method combines the day and net positions to give all the open positions in a User's Account.

### Holdings Method

- The `fetch_holdings ()` method gives an array of all the holdings of the USer's Account.


**Parameter:**

- `headers` (dict): headers to send the PositionBook/Holdings request with.

A PositionBook is an array of dictionaries with the following keys:

- `symbol`: Symbol of the Ticker for which the order is placed.

- `token`: Token of the Ticker.

- `product`: Product of the Order. Ex: MIS, NRML, etc.

- `netQty`: Total Quantity Bought and Sold for the Ticker.

- `avgPrice`: Average Price of the Position.

- `mtm`: Mark to Market value of the Ticker.

- `buyQty`: Total Buy Quantity,

- `buyPrice`: Average Buy Price.

- `sellQty`: Total Buy Quantity,

- `sellPrice`: Average Sell Price.

- `ltp`: Last Traded Price of the Ticker.

- `info`: A dictionary with the original broker json for the position.

### Position / Holding Structure

```python
{
    'symbol': 'BANKNIFTY23D0646600PE',
    'token': 41068,
    'product': 'MIS',
    'netQty': 0,
    'avgPrice': 313.4,
    'mtm': 129.0,
    'buyQty': 60,
    'buyPrice': 160.0,
    'sellQty': 60,
    'sellPrice': 162.15,
    'ltp': 49.55,
    'info': {
        'exchange': 'NFO',
        'cf_sell_amount': 0.0,
        'sell_quantity': 60,
        'average_price': 313.4,
        'segment': None,
        'average_buy_price': 160.0,
        'prod_type': 'MIS',
        'client_id': '6ANG11',
        'average_sell_price': 162.15,
        'actual_average_buy_price': 0.0,
        'cf_buy_quantity': 0,
        'trading_symbol': 'BANKNIFTY23D0646600PE',
        'product': 'MIS',
        'close_price': 313.4,
        'realized_mtm': 129.0,
        'symbol': 'BANKNIFTY',
        'buy_amount': 9600.0,
        'cf_sell_quantity': 0,
        'previous_close': 313.4,
        'token': 41068,
        'pro_cli': 'CLIENT',
        'sell_amount': 9729.0,
        'actual_cf_buy_amount': 0.0,
        'net_quantity': 0,
        'actual_cf_sell_amount': 0.0,
        'instrument_token': 41068,
        'buy_quantity': 60,
        'v_login_id': '6ANG11',
        'cf_buy_amount': 0.0,
        'multiplier': 1,
        'ltp': 49.55,
        'net_amount_mtm': 129.0,
        'actual_average_sell_price': 0.0
        }
    }
 ```


## User Profile Method

This method fetches the user's details provided by the Broker.

**Parameter:**

- `headers` (dict): headers to send the request with.

A profile is a dictionary with the following keys:

- `clientId`: Unique User ID of the User.

- `name`:  User's Name.

- `emailId`:  User's Email ID.

- `mobileNo`: User's Mobile No.

- `pan`: User's PAN No.

- `address`:  User's Address.

- `bankName`: Name of the User's Bank

- `bankBranchName`: Branch of the aformentioned Bank.

- `bankAccNo`: Bank Account No.

- `exchangesEnabled`: Exchanges Enabled for Trading in the User's Account.

- `enabled`: A `bool` value denoting whether the account is active or not.

- `info`: A dictionary with the original broker json for the position.

### Profile Structure

```python
{
    "clientId": "XA42X19",
    "name": "Hardeep Singh",
    "emailId": "hardeep.hd13@gmail.com",
    "mobileNo": "70X74X10X3",
    "pan": "XRXQSX6X6X",
    "address": "",
    "bankName": "HDFC BANK LTD",
    "bankBranchName": None,
    "bankAccNo": "5X1X0X5X1X9X45",
    "exchangesEnabled": ["NSE", "NIPO", "BSE", "BSTAR"],
    "enabled": True,
    "info": {
        "request_time": "17:43:01 22-11-2023",
        "actid": "XA42X19",
        "cliname": "Hardeep Singh",
        "act_sts": "Activated",
        "creatdte": "0",
        "creattme": "0",
        "m_num": "70X74X10X3",
        "email": "hardeep.hd13@gmail.com",
        "pan": "XRXQSX6X6X",
        "dob": "04-02-1996",
        "addr": "",
        "addroffice": "",
        "addrcity": "",
        "addrstate": "",
        "mandate_id_list": [],
        "exarr": ["NSE", "NIPO", "BSE", "BSTAR"],
        "bankdetails": [{
            "bankn": "HDFC BANK LTD",
            "acctnum": "5X1X0X5X1X9X45",
            "ifsc_code": "HDFC0X0X5X6"
            }],
        "dp_acct_num": [{"dpnum": "1X0X4X0X0X9X1X5X"}],
        "stat": "Ok"
        }
}
```


## RMS Limits Method

This method is used to Fetch Risk Management System Limits of a broker.

**Parameter:**

- `headers` (dict): headers to send the request with.

```python
rms_limits = kunjee.rms_limits(headers=headers)
```
