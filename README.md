# Fenix – Indian Broker Trading Library

![License](https://img.shields.io/badge/License-GPLv3-blue?color=%234ec820)


A Python library for trading in the Indian Finance Sector with support for many broker APIs.

### [Install](#install) · [Usage](#usage) · [Manual](https://github.com/TheHardeep/fenix/wiki)

The **Fenix** library is used to connect and trade with brokers in the Indian Financial Markets. It provides quick access to market data, order palcemement, etc. for storage, analysis, visualization, indicator development, algorithmic trading, strategy backtesting, bot programming, and related software engineering.

It is intended to be used by **coders, developers, technically-skilled traders, data-scientists and financial analysts** for building trading algorithms.

Current feature list:

- support for many brokers — more coming soon.
- optional normalized data for cross-exchange analytics.
- an out of the box unified API that is extremely easy to integrate.
- works in Python 3.



## Supported Indian Brokers

The fenix library currently supports the following 16 indian brokers and their trading APIs:




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




## Install


[fenix in **PyPI**](https://pypi.python.org/pypi/fenix)

```shell
pip install fenix
```

```Python
import fenix
print(fenix.brokers)
# print a list of all available exchange classes
```

## Documentation

Read the [Manual](https://github.com/TheHardeep/fenix/wiki) for more details.

## Usage

### Intro


The fenix library provides unifed methods for fetching market data, generating access tokens, placing different order types, fetching orderbook & tradebook, fetching order updates, etc.

In order to trade you need to provide your user credentials. It usually means signing up to the broker and creating API keys for your account. Some exchanges require personal info or identification. Sometimes verification may be necessary as well. In this case you will need to register yourself, this library will not create accounts or API keys for you.

Using this library you can perform the following:

- get instrument tokens for equity, options for both NSE & BSE.
- trade by making market, limit, stoploss and stoploss-market and bracket orders (if provided by the broker).
- modify and cancel open orders.
- query single order updates.
- query orderbook & tradebook.
- query positionbook.
- query holdings.
- query personal account info.
- query rms limits.


### Examples

```Python
# coding=utf-8

from fenix import aliceblue, angelone, zerodha, iifl
from fenix import constants


# Download all the FNO Intrument Tokens, Symbols, Lot Size
nfo_tokens = zerodha.create_fno_tokens()


# Create Headers which contain Access Token used to place orders, fetch orderbook, etc.
params = {
    "user_id": "YOUR_USER_ID",
    "password": 'YOUR_PASSWORD',
    "totpstr": 'YOUR_TOTP_STRING',
    "api_key": 'YOUR_API_KEY',
    "api_secret":'YOUR_API_SECRET'
    }

headers = zerodha.create_headers(params)


# Place a Limit Order in the FNO Segment
limit_order = zerodha.limit_order_fno(
                        price = 13.0,
                        option = "CE",
                        strike_price = 45500,
                        quantity = 15,
                        side = "BUY",
                        unique_id = 'LIMITOrderNFO',
                        headers = headers,
                        )


# Fetch the current detail of a single order
order_detail = zerodha.fetch_order('ORDER_ID', headers)


# Modify an open order
modified_order = zerodha.modify_order(
                            order_id='231217000002374',
                            price=10.0,
                            trigger=9.5,
                            quantity=15,
                            order_type=constants.OrderType.SL,
                            validity=constants.Validity.DAY,
                            headers=headers
                            )

# Cancel an open order
cancelled_order = zerodha.cancel_order(
                            order_id='231217000005603',
                            headers=headers
                            )

# Fetch OrderBook
orderbook = aliceblue.fetch_orders(headers=headers)


print(aliceblue.id, aliceblue.create_fno_tokens())
print(angelone.id, angelone.create_fno_tokens())
