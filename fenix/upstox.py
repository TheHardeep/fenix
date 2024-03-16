from __future__ import annotations
from typing import TYPE_CHECKING
from typing import Any

import time
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service as ChromeService

from fenix.base.exchange import Exchange

from fenix.base.constants import Side
from fenix.base.constants import OrderType
from fenix.base.constants import ExchangeCode
from fenix.base.constants import Product
from fenix.base.constants import Validity
from fenix.base.constants import Variety
from fenix.base.constants import Status
from fenix.base.constants import Order
from fenix.base.constants import Profile
from fenix.base.constants import Root
from fenix.base.constants import WeeklyExpiry
from fenix.base.constants import UniqueID


from fenix.base.errors import InputError
from fenix.base.errors import ResponseError
from fenix.base.errors import BrokerError
from fenix.base.errors import TokenDownloadError

if TYPE_CHECKING:
    from requests.models import Response


class upstox(Exchange):
    """
    UpStox fenix Broker Class.

    Returns:
        fenix.upstox: fenix UpStox Broker Object.
    """


    # Market Data Dictonaries

    indices = {}
    eq_tokens = {}
    nfo_tokens = {}
    token_params = ["api_key", "api_secret", "redirect_uri", "totpstr", "mobile_no", "pin"]
    id = 'upstox'
    _session = Exchange._create_session()


    # Base URLs

    base_urls = {
        "api_doc": "https://upstox.com/developer/api-documentation/open-api",
        "token_01": "https://api.upstox.com/v2/login/authorization/dialog?response_type=code&client_id=<api_key>&redirect_uri=<redirect_uri>",
        "token_02": "https://api.upstox.com/v2/login/authorization/token",
        "base": "https://api.upstox.com/v2",
        "market_data": "https://assets.upstox.com/market-quote/instruments/exchange/complete.csv.gz",
    }


    # Order Placing URLs

    urls = {
        "place_order": f"{base_urls['base']}/order/place",
        "modify_order": f"{base_urls['base']}/order/modify",
        "cancel_order": f"{base_urls['base']}/order/cancel",
        "order_history": f"{base_urls['base']}/order/history",
        "single_order": f"{base_urls['base']}/order/details",
        "orderbook": f"{base_urls['base']}/order/retrieve-all",
        "tradebook": f"{base_urls['base']}/order/trades/get-trades-for-day",
        "positions": f"{base_urls['base']}/portfolio/short-term-positions",
        "holdings": f"{base_urls['base']}/portfolio/long-term-holdings",
        "profile": f"{base_urls['base']}/user/profile",
    }


    # Request Parameters Dictionaries

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
        OrderType.MARKET: "MARKET",
        OrderType.LIMIT: "LIMIT",
        OrderType.SL: "SL",
        OrderType.SLM: "SL-M"
    }

    req_product = {
        Product.MIS: "I",
        Product.NRML: "D",
        Product.CNC: "CNC",
        Product.CO: "OCO",
        Product.BO: "I"
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


    # Response Parameters Dictionaries

    resp_order_type = {
        "MKT": OrderType.MARKET,
        "L": OrderType.LIMIT,
        "SL": OrderType.SL,
        "SL-M": OrderType.SLM,
    }

    resp_product = {
        "I": Product.MIS,
        "D": Product.NRML,
        "CNC": Product.CNC,
        "OCO": Product.CO,
    }

    resp_variety = {
        "SIMPLE": Variety.REGULAR,
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


    # NFO Script Fetch


    @classmethod
    def create_eq_tokens(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the upstox.indices Dictionary.

        Returns:
            dict: Unified fenix indices format.
        """
        df = cls.data_reader(link=cls.base_urls["market_data"], filetype="csv")

        df.rename({"tradingsymbol": "Symbol", "instrument_key": "Token",
                   "exchange_token": "ExchangeToken", "tick_size": "TickSize", "lot_size": "LotSize"
                   }, axis=1, inplace=True)



        df_bse = df[df['exchange'] == "BSE_EQ"]
        df_bse = df_bse[["Symbol", "Token", "ExchangeToken", "TickSize", "LotSize"]]
        df_bse["ExchangeToken"] = df_bse["ExchangeToken"].astype(int)
        df_bse.set_index(df_bse['Symbol'], inplace=True)
        df_bse.drop_duplicates(subset=['Symbol'], keep='first', inplace=True)


        df_nse = df[df['exchange'] == "NSE_EQ"]
        df_nse = df_nse[["Symbol", "Token", "ExchangeToken", "TickSize", "LotSize"]]
        df_nse["ExchangeToken"] = df_nse["ExchangeToken"].astype(int)
        df_nse.set_index(df_nse['Symbol'], inplace=True)
        df_nse.drop_duplicates(subset=['Symbol'], keep='first', inplace=True)


        cls.eq_tokens[ExchangeCode.NSE] = df_nse.to_dict(orient='index')
        cls.eq_tokens[ExchangeCode.BSE] = df_bse.to_dict(orient='index')

        return cls.eq_tokens


    @classmethod
    def create_indices(cls) -> dict:
        """
        Gives Indices Info for F&O Segment.
        Stores them in the upstox.indices Dictionary.

        Returns:
            dict: Unified fenix indices format.
        """
        df = cls.data_reader(link=cls.base_urls["market_data"], filetype="csv")

        df = df[df["exchange"] == "NSE_INDEX"][["name", "instrument_key", "exchange_token"]]

        df.rename({"instrument_key": "Symbol", "exchange_token": "Token"}, axis=1, inplace=True)
        df.index = df["name"]
        del df["name"]
        indices = df.to_dict(orient="index")

        indices[Root.BNF] = indices["Nifty Bank"]
        indices[Root.NF] = indices["Nifty 50"]
        indices[Root.FNF] = indices["Nifty Fin Service"]
        indices[Root.MIDCPNF] = indices["NIFTY MID SELECT"]

        cls.indices = indices

        return indices

    @classmethod
    def create_nfo_tokens(cls) -> dict:
        """
        Creates BANKNIFTY & NIFTY Current, Next and Far Expiries;
        Stores them in the upstox.nfo_tokens Dictionary.

        Raises:
            TokenDownloadError: Any Error Occured is raised through this Error Type.
        """
        try:
            df = cls.data_reader(link=cls.base_urls["market_data"], filetype="csv")

            df = df[(df["instrument_type"] == "OPTIDX") & (df["exchange"] == "NSE_FO")]
            df["Root"] = df["tradingsymbol"].str.extract(r"(FINNIFTY|MIDCPNIFTY|BANKNIFTY|NIFTY)\w+", expand=False)

            df.rename({"option_type": "Option", "instrument_key": "Token",
                       "expiry": "Expiry", "tradingsymbol": "Symbol",
                       "tick_size": "TickSize", "lot_size": "LotSize",
                       "strike": "StrikePrice", "exchange_token": "ExchangeToken",
                       }, axis=1, inplace=True)

            df = df[["Token", "Symbol", "ExchangeToken", "Expiry", "Option", "StrikePrice",
                     "LotSize", "Root", "TickSize"
                     ]]

            df["StrikePrice"] = df["StrikePrice"].astype(int)
            df["ExchangeToken"] = df["ExchangeToken"].astype(int)
            df["Expiry"] = cls.pd_datetime(df["Expiry"]).dt.date.astype(str)

            expiry_data = cls.jsonify_expiry(data_frame=df)
            cls.nfo_tokens = expiry_data

            return expiry_data

        except Exception as exc:
            import traceback
            raise TokenDownloadError({"Error": exc.args}) from exc


    # Headers & Json Parsers


    @classmethod
    def create_headers(cls,
                       params: dict,
                       ) -> dict[str, str]:
        """
        Generate Headers used to access Endpoints in UpStox.

        Parameters:
            Params (dict) : A dictionary which should consist the following keys:
                api_key (str): API Key of the Account, created on the APP.
                api_secret (str): API Secret of the Account, created on the APP.
                redirect_uri (str): Redirect URI of the Account, created on the APP.
                totpstr (str): String of characters used to generate TOTP.
                mobile_no (str): Mobile Number of the Account Holder, without country code.
                pin (str): PIN of the Acccount.

        Returns:
            dict[str, str]: UpStox Headers.
        """
        for key in cls.token_params:
            if key not in params:
                raise KeyError(f"Please provide {key}")


        dialog_url = cls.base_urls["token_01"].replace("<api_key>", params["api_key"]).replace("<redirect_uri>", params["redirect_uri"])


        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument(
            "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36")

        driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()),
                                  options=options
                                  )

        driver.get(dialog_url)

        elem = driver.find_element(By.ID, "mobileNum")
        elem.clear()
        elem.send_keys(params["mobile_no"])

        c1 = driver.find_element(By.ID, "getOtp")
        c1.click()


        totp = cls.totp_creator(params["totpstr"])
        elem = WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, "otpNum")))
        elem.clear()
        elem.send_keys(totp)

        c1 = driver.find_element(By.ID, "continueBtn")
        c1.click()


        elem = WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, "pinCode")))
        elem.clear()
        elem.send_keys(params["pin"])

        c1 = driver.find_element(By.ID, "pinContinueBtn")
        c1.click()


        time.sleep(1)
        for i in range(5):
            code = driver.current_url.split("code=")
            if len(code) > 1:
                code = code[-1]
                break
            else:
                time.sleep(2)

        driver.quit()


        headers = {
            'accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        data = {
            "code": code,
            "client_id": params['api_key'],
            "client_secret": params["api_secret"],
            "redirect_uri": params["redirect_uri"],
            "grant_type": "authorization_code",
        }

        response = cls.fetch(method="POST", url=cls.base_urls["token_02"],
                             data=data, headers=headers)
        info = cls.on_json_response(response)
        access_token = info["access_token"]

        headers = {
            "headers": {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
        }

        cls._session = cls._create_session()

        return headers

    @classmethod
    def _json_parser(cls,
                     response: Response
                     ) -> dict[Any, Any] | list[dict[Any, Any]]:
        """
        Parses the Json Repsonse Obtained from Broker.

        Parameters:
            response (Response): Json Response Obtained from Broker.

        Raises:
            ResponseError: Raised if any error received from broker.

        Returns:
            dict: json response obtained from exchange.
        """
        json_response = cls.on_json_response(response)
        # print(json_response)

        if json_response["status"] == "success":
            return json_response

        raise ResponseError(cls.id + " " + json_response["errors"][0]["message"])

    @classmethod
    def _orderbook_json_parser(cls,
                               order: dict,
                               ) -> dict[Any, Any]:
        """
        Parse Orderbook Order Json Response.

        Parameters:
            order (dict): Orderbook Order Json Response from Broker.

        Returns:
            dict: Unified fenix Order Response.
        """
        parsed_order = {
            Order.ID: order["order_id"],
            Order.USERID: order["tag"],
            Order.TIMESTAMP: cls.datetime_strp(order["order_timestamp"], "%Y-%m-%d %H:%M:%S"),
            Order.SYMBOL: order["trading_symbol"],
            Order.TOKEN: order["instrument_token"].split("|")[-1],
            Order.SIDE: cls.req_side.get(order["transaction_type"], order["transaction_type"]),
            Order.TYPE: cls.resp_order_type.get(order["order_type"], order["order_type"]),
            Order.AVGPRICE: order["average_price"],
            Order.PRICE: order["price"],
            Order.TRIGGERPRICE: order["trigger_price"],
            Order.TARGETPRICE: None,
            Order.STOPLOSSPRICE: None,
            Order.TRAILINGSTOPLOSS: None,
            Order.QUANTITY: order["quantity"],
            Order.FILLEDQTY: order["filled_quantity"],
            Order.REMAININGQTY: order.get("pending_quantity", 0),
            Order.CANCELLEDQTY: None,
            Order.STATUS: cls.resp_status.get(order["status"], order["status"]),
            Order.REJECTREASON: order.get("status_message_raw", ""),
            Order.DISCLOSEDQUANTITY: order["disclosed_quantity"],
            Order.PRODUCT: cls.resp_product.get(order["product"], order["product"]),
            Order.EXCHANGE: cls.req_exchange.get(order["exchange"], order["exchange"]),
            Order.SEGMENT: cls.req_exchange.get(order["exchange"], order["exchange"]),
            Order.VALIDITY: cls.req_validity.get(order["validity"], order["validity"]),
            Order.VARIETY: cls.resp_variety.get(order["variety"], order["variety"]),
            Order.INFO: order,
        }

        return parsed_order

    @classmethod
    def _profile_json_parser(cls,
                             profile: dict
                             ) -> dict[Any, Any]:
        """
        Parse User Profile Json Response.

        Parameters:
            profile (dict): User Profile Json Response from Broker.

        Returns:
            dict: Unified fenix Profile Response.
        """
        exchanges_enabled = [cls.req_exchange.get(i, i) for i in profile['exchanges']]

        parsed_profile = {
            Profile.CLIENTID: profile['user_id'],
            Profile.NAME: profile['user_name'],
            Profile.EMAILID: profile['email'],
            Profile.MOBILENO: "",
            Profile.PAN: "",
            Profile.ADDRESS: "",
            Profile.BANKNAME: "",
            Profile.BANKBRANCHNAME: None,
            Profile.BANKACCNO: "",
            Profile.EXHCNAGESENABLED: exchanges_enabled,
            Profile.ENABLED: profile['is_active'],
            Profile.INFO: profile,
        }

        return parsed_profile

    @classmethod
    def _create_order_parser(cls,
                             response: Response,
                             headers: dict
                             ) -> dict[Any, Any]:
        """
        Parse Json Response Obtained from Broker After Placing Order to get order_id
        and fetching the json repsone for the said order_id.

        Parameters:
            response (Response): Json Repsonse Obtained from broker after Placing an Order.
            headers (dict): headers to send order request with.

        Returns:
            dict: Unified fenix Order Response.
        """
        info = cls._json_parser(response)

        order_id = info["data"]["order_id"]
        order = cls.fetch_order(order_id=order_id, headers=headers)

        return order


    # Order Functions


    @classmethod
    def create_eq_nfo_order(cls,
                            quantity: int,
                            side: str,
                            headers: dict,
                            token_dict: dict,
                            price: float = 0.0,
                            trigger: float = 0.0,
                            product: str = Product.MIS,
                            validity: str = Validity.DAY,
                            variety: str = Variety.REGULAR,
                            unique_id: str = UniqueID.DEFORDER
                            ) -> dict[Any, Any]:
        """
        Place an Order in F&O and Equity Segment.

        Parameters:
            quantity (int): Order quantity.
            side (str): Order Side: "BUY", "SELL".
            headers (dict): headers to send order request with.
            token_dict (dict): a dictionary with details of the Ticker. Obtianed from eq_tokens or nfo_tokens.
            price (float): price of the order. Defaults to 0.0.
            trigger (float): trigger price of the order. Defaults to 0.0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.DEFORDER.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL

        token = token_dict["Token"]

        json_data = {
            "instrument_token": token,
            "price": price,
            "trigger_price": trigger,
            "quantity": quantity,
            "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
            "order_type": cls.req_order_type[order_type],
            "product": cls._key_mapper(cls.req_product, product, 'product'),
            "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
            "tag": unique_id,
            "disclosed_quantity": 0,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def create_order(cls,
                     token: int,
                     exchange: str,
                     symbol: str,
                     quantity: int,
                     side: str,
                     product: str,
                     validity: str,
                     variety: str,
                     unique_id: str,
                     headers: dict,
                     price: float = 0.0,
                     trigger: float = 0.0,
                     target: float = 0.0,
                     stoploss: float = 0.0,
                     trailing_sl: float = 0.0,
                     ) -> dict[Any, Any]:

        """
        Place an Order.

        Parameters:
            token (int): Exchange token.
            exchange (str): Exchange to place the order in.
            symbol (str): Trading symbol.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            product (str, optional): Order product.
            validity (str, optional): Order validity.
            variety (str, optional): Order variety.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            price (float): Order price
            trigger (float): order trigger price
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL

        if not target:
            json_data = {
                "instrument_token": token,
                "price": price,
                "trigger_price": trigger,
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
                "order_type": cls.req_order_type[order_type],
                "product": cls._key_mapper(cls.req_product, product, 'product'),
                "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
                "tag": unique_id,
                "disclosed_quantity": 0,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")


        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order(cls,
                     token: int,
                     exchange: str,
                     symbol: str,
                     quantity: int,
                     side: str,
                     unique_id: str,
                     headers: dict,
                     target: float = 0.0,
                     stoploss: float = 0.0,
                     trailing_sl: float = 0.0,
                     product: str = Product.MIS,
                     validity: str = Validity.DAY,
                     variety: str = Variety.REGULAR,
                     ) -> dict[Any, Any]:
        """
        Place Market Order.

        Parameters:
            token (int): Exchange token.
            exchange (str): Exchange to place the order in.
            symbol (str): Trading symbol.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not target:
            json_data = {
                "instrument_token": token,
                "price": 0,
                "trigger_price": 0,
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
                "order_type": cls.req_order_type[OrderType.MARKET],
                "product": cls._key_mapper(cls.req_product, product, 'product'),
                "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
                "tag": unique_id,
                "disclosed_quantity": 0,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order(cls,
                    token: int,
                    exchange: str,
                    symbol: str,
                    price: float,
                    quantity: int,
                    side: str,
                    unique_id: str,
                    headers: dict,
                    target: float = 0.0,
                    stoploss: float = 0.0,
                    trailing_sl: float = 0.0,
                    product: str = Product.MIS,
                    validity: str = Validity.DAY,
                    variety: str = Variety.REGULAR,
                    ) -> dict[Any, Any]:
        """
        Place Limit Order.

        Parameters:
            token (int): Exchange token.
            exchange (str): Exchange to place the order in.
            symbol (str): Trading symbol.
            price (float): Order price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not target:
            json_data = {
                "instrument_token": token,
                "price": price,
                "trigger_price": 0,
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
                "order_type": cls.req_order_type[OrderType.LIMIT],
                "product": cls._key_mapper(cls.req_product, product, 'product'),
                "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
                "tag": unique_id,
                "disclosed_quantity": 0,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order(cls,
                 token: int,
                 exchange: str,
                 symbol: str,
                 price: float,
                 trigger: float,
                 quantity: int,
                 side: str,
                 unique_id: str,
                 headers: dict,
                 target: float = 0.0,
                 stoploss: float = 0.0,
                 trailing_sl: float = 0.0,
                 product: str = Product.MIS,
                 validity: str = Validity.DAY,
                 variety: str = Variety.STOPLOSS,
                 ) -> dict[Any, Any]:
        """
        Place Stoploss Order.

        Parameters:
            token (int): Exchange token.
            exchange (str): Exchange to place the order in.
            symbol (str): Trading symbol.
            price (float): Order price.
            trigger (float): order trigger price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not target:
            json_data = {
                "instrument_token": token,
                "price": price,
                "trigger_price": trigger,
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
                "order_type": cls.req_order_type[OrderType.SL],
                "product": cls._key_mapper(cls.req_product, product, 'product'),
                "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
                "tag": unique_id,
                "disclosed_quantity": 0,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order(cls,
                  token: int,
                  exchange: str,
                  symbol: str,
                  trigger: float,
                  quantity: int,
                  side: str,
                  unique_id: str,
                  headers: dict,
                  target: float = 0.0,
                  stoploss: float = 0.0,
                  trailing_sl: float = 0.0,
                  product: str = Product.MIS,
                  validity: str = Validity.DAY,
                  variety: str = Variety.STOPLOSS,
                  ) -> dict[Any, Any]:
        """
        Place Stoploss-Market Order.

        Parameters:
            token (int): Exchange token.
            exchange (str): Exchange to place the order in.
            symbol (str): Trading symbol.
            trigger (float): order trigger price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not target:
            json_data = {
                "instrument_token": token,
                "price": 0,
                "trigger_price": trigger,
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
                "order_type": cls.req_order_type[OrderType.SLM],
                "product": cls._key_mapper(cls.req_product, product, 'product'),
                "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
                "tag": unique_id,
                "disclosed_quantity": 0,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)


    # Equity Order Functions


    @classmethod
    def create_order_eq(cls,
                        exchange: str,
                        symbol: str,
                        quantity: int,
                        side: str,
                        product: str,
                        validity: str,
                        variety: str,
                        unique_id: str,
                        headers: dict,
                        price: float = 0.0,
                        trigger: float = 0.0,
                        target: float = 0.0,
                        stoploss: float = 0.0,
                        trailing_sl: float = 0.0,
                        ) -> dict[Any, Any]:

        """
        Place an Order in NSE/BSE Equity Segment.

        Parameters:
            exchange (str): Exchange to place the order in. Possible Values: NSE, BSE.
            symbol (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            product (str, optional): Order product.
            validity (str, optional): Order validity.
            variety (str, optional): Order variety.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            price (float): Order price
            trigger (float): order trigger price
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL

        if not target:
            json_data = {
                "instrument_token": token,
                "price": price,
                "trigger_price": trigger,
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
                "order_type": cls.req_order_type[order_type],
                "product": cls._key_mapper(cls.req_product, product, 'product'),
                "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
                "tag": unique_id,
                "disclosed_quantity": 0,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")


        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order_eq(cls,
                        exchange: str,
                        symbol: str,
                        quantity: int,
                        side: str,
                        unique_id: str,
                        headers: dict,
                        target: float = 0.0,
                        stoploss: float = 0.0,
                        trailing_sl: float = 0.0,
                        product: str = Product.MIS,
                        validity: str = Validity.DAY,
                        variety: str = Variety.REGULAR,
                        ) -> dict[Any, Any]:
        """
        Place Market Order in NSE/BSE Equity Segment.

        Parameters:
            exchange (str): Exchange to place the order in. Possible Values: NSE, BSE.
            symbol (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        if not target:
            json_data = {
                "instrument_token": token,
                "price": 0,
                "trigger_price": 0,
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
                "order_type": cls.req_order_type[OrderType.MARKET],
                "product": cls._key_mapper(cls.req_product, product, 'product'),
                "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
                "tag": unique_id,
                "disclosed_quantity": 0,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order_eq(cls,
                       exchange: str,
                       symbol: str,
                       price: float,
                       quantity: int,
                       side: str,
                       unique_id: str,
                       headers: dict,
                       target: float = 0.0,
                       stoploss: float = 0.0,
                       trailing_sl: float = 0.0,
                       product: str = Product.MIS,
                       validity: str = Validity.DAY,
                       variety: str = Variety.REGULAR,
                       ) -> dict[Any, Any]:
        """
        Place Limit Order in NSE/BSE Equity Segment.

        Parameters:
            exchange (str): Exchange to place the order in. Possible Values: NSE, BSE.
            symbol (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"
            price (float): Order price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        if not target:
            json_data = {
                "instrument_token": token,
                "price": price,
                "trigger_price": 0,
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
                "order_type": cls.req_order_type[OrderType.LIMIT],
                "product": cls._key_mapper(cls.req_product, product, 'product'),
                "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
                "tag": unique_id,
                "disclosed_quantity": 0,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order_eq(cls,
                    exchange: str,
                    symbol: str,
                    price: float,
                    trigger: float,
                    quantity: int,
                    side: str,
                    unique_id: str,
                    headers: dict,
                    target: float = 0.0,
                    stoploss: float = 0.0,
                    trailing_sl: float = 0.0,
                    product: str = Product.MIS,
                    validity: str = Validity.DAY,
                    variety: str = Variety.STOPLOSS,
                    ) -> dict[Any, Any]:
        """
        Place Stoploss Order in NSE/BSE Equity Segment.

        Parameters:
            exchange (str): Exchange to place the order in. Possible Values: NSE, BSE.
            symbol (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"
            price (float): Order price.
            trigger (float): order trigger price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        if not target:
            json_data = {
                "instrument_token": token,
                "price": price,
                "trigger_price": trigger,
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
                "order_type": cls.req_order_type[OrderType.SL],
                "product": cls._key_mapper(cls.req_product, product, 'product'),
                "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
                "tag": unique_id,
                "disclosed_quantity": 0,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order_eq(cls,
                     exchange: str,
                     symbol: str,
                     trigger: float,
                     quantity: int,
                     side: str,
                     unique_id: str,
                     headers: dict,
                     target: float = 0.0,
                     stoploss: float = 0.0,
                     trailing_sl: float = 0.0,
                     product: str = Product.MIS,
                     validity: str = Validity.DAY,
                     variety: str = Variety.STOPLOSS,
                     ) -> dict[Any, Any]:
        """
        Place Stoploss-Market Order in NSE/BSE Equity Segment.

        Parameters:
            exchange (str): Exchange to place the order in. Possible Values: NSE, BSE.
            symbol (str): Trading symbol, the same one you use on TradingView. Ex: "RELIANCE", "BHEL"
            trigger (float): order trigger price.
            quantity (int): Order quantity.
            side (str): Order Side: BUY, SELL.
            unique_id (str): Unique user order_id.
            headers (dict): headers to send order request with.
            target (float, optional): Order Target price. Defaults to 0.
            stoploss (float, optional): Order Stoploss price. Defaults to 0.
            trailing_sl (float, optional): Order Trailing Stoploss percent. Defaults to 0.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity. Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.REGULAR.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.eq_tokens:
            cls.create_eq_tokens()

        exchange = cls._key_mapper(cls.req_exchange, exchange, 'exchange')
        detail = cls._eq_mapper(cls.eq_tokens[exchange], symbol)
        token = detail["Token"]

        if not target:
            json_data = {
                "instrument_token": token,
                "price": 0,
                "trigger_price": trigger,
                "quantity": quantity,
                "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
                "order_type": cls.req_order_type[OrderType.SLM],
                "product": cls._key_mapper(cls.req_product, product, 'product'),
                "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
                "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
                "tag": unique_id,
                "disclosed_quantity": 0,
            }

        else:
            raise InputError(f"BO Orders Not Available in {cls.id}.")

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)


    # NFO Order Functions


    @classmethod
    def create_order_nfo(cls,
                         exchange: str,
                         root: str,
                         expiry: str,
                         option: str,
                         strike_price: int,
                         quantity: int,
                         side: str,
                         product: str,
                         validity: str,
                         variety: str,
                         unique_id: str,
                         headers: dict,
                         price: float = 0.0,
                         trigger: float = 0.0,
                         ) -> dict[Any, Any]:
        """
        Place an Order in F&O Segment.

        Parameters:
            option (str): Option Type: 'CE', 'PE'.
            strike_price (int): Strike Price of the Option.
            price (float): price of the order.
            trigger (float): trigger price of the order.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional): Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']


        if not price and trigger:
            order_type = OrderType.SLM
        elif not price:
            order_type = OrderType.MARKET
        elif not trigger:
            order_type = OrderType.LIMIT
        else:
            order_type = OrderType.SL

        json_data = {
            "instrument_token": token,
            "price": price,
            "trigger_price": trigger,
            "quantity": quantity,
            "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
            "order_type": cls.req_order_type[order_type],
            "product": cls._key_mapper(cls.req_product, product, 'product'),
            "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
            "tag": unique_id,
            "disclosed_quantity": 0,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def market_order_nfo(cls,
                         option: str,
                         strike_price: int,
                         quantity: int,
                         side: str,
                         headers: dict,
                         root: str = Root.BNF,
                         expiry: str = WeeklyExpiry.CURRENT,
                         exchange: str = ExchangeCode.NFO,
                         product: str = Product.MIS,
                         validity: str = Validity.DAY,
                         variety: str = Variety.REGULAR,
                         unique_id: str = UniqueID.MARKETORDER,
                         ) -> dict[Any, Any]:
        """
        Place Market Order in F&O Segment.

        Parameters:
            option (str): Option Type: 'CE', 'PE'.
            strike_price (int): Strike Price of the Option.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional): Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        json_data = {
            "instrument_token": token,
            "price": 0,
            "trigger_price": 0,
            "quantity": quantity,
            "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
            "order_type": cls.req_order_type[OrderType.MARKET],
            "product": cls._key_mapper(cls.req_product, product, 'product'),
            "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
            "tag": unique_id,
            "disclosed_quantity": 0,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order_nfo(cls,
                        option: str,
                        strike_price: int,
                        price: float,
                        quantity: int,
                        side: str,
                        headers: dict,
                        root: str = Root.BNF,
                        expiry: str = WeeklyExpiry.CURRENT,
                        exchange: str = ExchangeCode.NFO,
                        product: str = Product.MIS,
                        validity: str = Validity.DAY,
                        variety: str = Variety.REGULAR,
                        unique_id: str = UniqueID.LIMITORDER,
                        ) -> dict[Any, Any]:
        """
        Place Limit Order in F&O Segment.

        Parameters:
            option (str): Option Type: 'CE', 'PE'.
            strike_price (int): Strike Price of the Option.
            price (float): price of the order.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional): Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        json_data = {
            "instrument_token": token,
            "price": price,
            "trigger_price": 0,
            "quantity": quantity,
            "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
            "order_type": cls.req_order_type[OrderType.LIMIT],
            "product": cls._key_mapper(cls.req_product, product, 'product'),
            "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
            "tag": unique_id,
            "disclosed_quantity": 0,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order_nfo(cls,
                     option: str,
                     strike_price: int,
                     price: float,
                     trigger: float,
                     quantity: int,
                     side: str,
                     headers: dict,
                     root: str = Root.BNF,
                     expiry: str = WeeklyExpiry.CURRENT,
                     exchange: str = ExchangeCode.NFO,
                     product: str = Product.MIS,
                     validity: str = Validity.DAY,
                     variety: str = Variety.STOPLOSS,
                     unique_id: str = UniqueID.SLORDER,
                     ) -> dict[Any, Any]:
        """
        Place Stoploss Order in F&O Segment.

        Parameters:
            option (str): Option Type: 'CE', 'PE'.
            strike_price (int): Strike Price of the Option.
            price (float): price of the order.
            trigger (float): trigger price of the order.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional): Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        json_data = {
            "instrument_token": token,
            "price": price,
            "trigger_price": trigger,
            "quantity": quantity,
            "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
            "order_type": cls.req_order_type[OrderType.SL],
            "product": cls._key_mapper(cls.req_product, product, 'product'),
            "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
            "tag": unique_id,
            "disclosed_quantity": 0,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def slm_order_nfo(cls,
                      option: str,
                      strike_price: int,
                      trigger: float,
                      quantity: int,
                      side: str,
                      headers: dict,
                      root: str = Root.BNF,
                      expiry: str = WeeklyExpiry.CURRENT,
                      exchange: str = ExchangeCode.NFO,
                      product: str = Product.MIS,
                      validity: str = Validity.DAY,
                      variety: str = Variety.STOPLOSS,
                      unique_id: str = UniqueID.SLORDER,
                      ) -> dict[Any, Any]:
        """
        Place Stoploss-Market Order in F&O Segment.

        Parameters:
            option (str): Option Type: 'CE', 'PE'.
            strike_price (int): Strike Price of the Option.
            trigger (float): trigger price of the order.
            quantity (int): Order quantity.
            side (str): Order Side: 'BUY', 'SELL'.
            headers (dict): headers to send order request with.
            root (str): Derivative: BANKNIFTY, NIFTY.
            expiry (str, optional): Expiry of the Option: 'CURRENT', 'NEXT', 'FAR'. Defaults to WeeklyExpiry.CURRENT.
            unique_id (str, optional): Unique user orderid. Defaults to UniqueID.MARKETORDER.
            exchange (str, optional): Exchange to place the order in. Defaults to ExchangeCode.NFO.
            product (str, optional): Order product. Defaults to Product.MIS.
            validity (str, optional): Order validity Defaults to Validity.DAY.
            variety (str, optional): Order variety Defaults to Variety.DAY.

        Raises:
            KeyError: If Strike Price Does not Exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        if not cls.nfo_tokens:
            cls.create_nfo_tokens()

        detail = cls.nfo_tokens[expiry][root][option]
        detail = detail.get(strike_price, None)

        if not detail:
            raise KeyError(f"StrikePrice: {strike_price} Does not Exist")

        token = detail['Token']

        json_data = {
            "instrument_token": token,
            "price": 0,
            "trigger_price": trigger,
            "quantity": quantity,
            "transaction_type": cls._key_mapper(cls.req_side, side, 'side'),
            "order_type": cls.req_order_type[OrderType.SLM],
            "product": cls._key_mapper(cls.req_product, product, 'product'),
            "validity": cls._key_mapper(cls.req_validity, validity, 'validity'),
            "is_amo": False if cls._key_mapper(cls.req_variety, variety, 'variety') != Variety.AMO else True,
            "tag": unique_id,
            "disclosed_quantity": 0,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)


    # BO Order Functions

    # NO BO Orders For Upstox


    # Order Details, OrderBook & TradeBook


    @classmethod
    def fetch_raw_orderbook(cls,
                            headers: dict
                            ) -> list[dict]:
        """
        Fetch Raw Orderbook Details, without any Standardaization.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: Raw Broker Orderbook Response.
        """
        response = cls.fetch(method="GET", url=cls.urls["orderbook"], headers=headers["headers"])
        return cls._json_parser(response)

    @classmethod
    def fetch_raw_orderhistory(cls,
                               order_id: str,
                               headers: dict
                               ) -> list[dict]:
        """
        Fetch Raw History of an order.

        Paramters:
            order_id (str): id of the order.
            headers (dict): headers to send orderhistory request with.

        Returns:
            list[dict]: Raw Broker Order History Response.
        """
        params = {"order_id": order_id}
        try:
            response = cls.fetch(method="GET", url=cls.urls["order_history"],
                                 params=params, headers=headers["headers"])
        except BrokerError as e:
            if "Order not found" in str(e):
                raise InputError({"This order_id does not exist."})

        return cls._json_parser(response)

    @classmethod
    def fetch_raw_order(cls,
                        order_id: str,
                        headers: dict
                        ) -> dict[Any, Any]:
        """
        Fetch Raw Detail of an order.

        Paramters:
            order_id (str): id of the order.
            headers (dict): headers to send order detail request with.

        Returns:
            list[dict]: Raw Broker Order Detail Response.
        """
        params = {"order_id": order_id}
        try:
            response = cls.fetch(method="GET", url=cls.urls["single_order"],
                                 params=params, headers=headers["headers"])
        except BrokerError as e:
            if "Order not found" in str(e):
                raise InputError({"This order_id does not exist."})

        return cls._json_parser(response)

    @classmethod
    def fetch_orderbook(cls,
                        headers: dict
                        ) -> list[dict]:
        """
        Fetch Orderbook Details.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: List of dicitonaries of orders using fenix Unified Order Response.
        """
        info = cls.fetch_raw_orderbook(headers=headers)

        orders = []
        for order in info["data"]:
            detail = cls._orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_tradebook(cls,
                        headers: dict
                        ) -> list[dict]:
        """
        Fetch Tradebook Details.

        Parameters:
            headers (dict): headers to send fetch_orders request with.

        Returns:
            list[dict]: List of dicitonaries of orders using fenix Unified Order Response.
        """
        response = cls.fetch(method="GET", url=cls.urls["tradebook"], headers=headers["headers"])
        info = cls._json_parser(response)

        orders = []
        for order in info["data"]:
            detail = cls._orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_orders(cls,
                     headers: dict
                     ) -> list[dict]:
        """
        Fetch OrderBook Details which is unified across all brokers.
        Use This if you want Avg price, etc. values which sometimes unavailable
        thorugh fetch_orderbook.

        Paramters:
            order_id (str): id of the order.

        Raises:
            InputError: If order does not exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        return cls.fetch_orderbook(headers=headers)

    @classmethod
    def fetch_order(cls,
                    order_id: str,
                    headers: dict
                    ) -> dict[Any, Any]:
        """
        Fetch Order Details.

        Paramters:
            order_id (str): id of the order.

        Raises:
            InputError: If order does not exist.

        Returns:
            dict: fenix Unified Order Response.
        """
        info = cls.fetch_raw_order(order_id=order_id, headers=headers)
        return cls._orderbook_json_parser(info["data"])

    @classmethod
    def fetch_orderhistory(cls,
                           order_id: str,
                           headers: dict
                           ) -> list[dict]:
        """
        Fetch History of an order.

        Paramters:
            order_id (str): id of the order.
            headers (dict): headers to send orderhistory request with.

        Returns:
            list: A list of dicitonaries containing order history using fenix Unified Order Response.
        """
        info = cls.fetch_raw_orderhistory(order_id=order_id, headers=headers)

        order_history = []
        for order in info["data"]:
            history = cls._orderbook_json_parser(order)
            order_history.append(history)

        return order_history


    # Order Modification & Sq Off


    @classmethod
    def modify_order(cls,
                     order_id: str,
                     headers: dict,
                     price: float | None = None,
                     trigger: float | None = None,
                     quantity: int | None = None,
                     order_type: str | None = None,
                     validity: str | None = None,
                     ) -> dict[Any, Any]:
        """
        Modify an open order.

        Parameters:
            order_id (str): id of the order to modify.
            headers (dict): headers to send modify_order request with.
            price (float | None, optional): price of t.he order. Defaults to None.
            trigger (float | None, optional): trigger price of the order. Defaults to None.
            quantity (int | None, optional): order quantity. Defaults to None.
            order_type (str | None, optional): Type of Order. defaults to None.
            validity (str | None, optional): Order validity Defaults to None.

        Returns:
            dict: fenix Unified Order Response.
        """
        order_info = cls.fetch_raw_order(order_id=order_id, headers=headers)
        order_info = order_info["data"]

        json_data = {
            "order_id": order_info["order_id"],
            "price": price or order_info["price"],
            "trigger_price": trigger or order_info["trigger_price"],
            "quantity": quantity or order_info["quantity"],
            "order_type": cls._key_mapper(cls.req_order_type, order_type, 'order_type') if order_type else order_info["order_type"],
            "validity": cls.req_validity.get(validity, order_info["validity"]) if validity else order_info["validity"],
            "disclosed_quantity": 0,
        }

        response = cls.fetch(method="PUT", url=cls.urls["modify_order"],
                             json=json_data, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)

    @classmethod
    def cancel_order(cls,
                     order_id: str,
                     headers: dict
                     ) -> dict[Any, Any]:
        """
        Cancel an open order.

        Parameters:
            order_id (str): id of the order.
            headers (dict): headers to send cancel_order request with.

        Returns:
            dict: fenix Unified Order Response.
        """
        params = {"order_id": order_id}
        response = cls.fetch(method="DELETE", url=cls.urls["cancel_order"],
                             params=params, headers=headers["headers"])

        return cls._create_order_parser(response=response, headers=headers)


    # Positions, Account Limits & Profile


    @classmethod
    def fetch_day_positions(cls,
                            headers: dict,
                            ) -> dict[Any, Any]:
        """
        Fetch the Day's Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        response = cls.fetch(method="GET", url=cls.urls['positions'], headers=headers["headers"])
        return cls._json_parser(response)

    @classmethod
    def fetch_net_positions(cls,
                            headers: dict,
                            ) -> dict[Any, Any]:
        """
        Fetch Total Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        return cls.fetch_day_positions(headers=headers)

    @classmethod
    def fetch_positions(cls,
                        headers: dict,
                        ) -> dict[Any, Any]:
        """
        Fetch Day & Net Account Positions.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Position Response.
        """
        return cls.fetch_day_positions(headers=headers)

    @classmethod
    def fetch_holdings(cls,
                       headers: dict,
                       ) -> dict[Any, Any]:
        """
        Fetch Account Holdings.

        Args:
            headers (dict): headers to send rms_limits request with.

        Returns:
            dict[Any, Any]: fenix Unified Positions Response.
        """
        response = cls.fetch(method="GET", url=cls.urls['holdings'], headers=headers["headers"])
        return cls._json_parser(response)

    @classmethod
    def profile(cls,
                headers: dict
                ) -> dict[Any, Any]:
        """
        Fetch Profile Limits of the User.

        Parameters:
            headers (dict): headers to send profile request with.

        Returns:
            dict: fenix Unified Profile Response.
        """
        response = cls.fetch(method="GET", url=cls.urls["profile"], headers=headers["headers"])
        response = cls._json_parser(response)

        profile = cls._profile_json_parser(response["data"])
        return profile
