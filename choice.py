from __future__ import annotations
import base64
from typing import TYPE_CHECKING
from typing import Any
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


from kronos.base.exchange import Exchange

from kronos.base.constants import Side
from kronos.base.constants import OrderType
from kronos.base.constants import ExchangeCode
from kronos.base.constants import Product
from kronos.base.constants import Validity
from kronos.base.constants import Order
from kronos.base.constants import Status
from kronos.base.constants import Profile

from kronos.base.errors import TokenDownloadError
from kronos.base.errors import ResponseError


if TYPE_CHECKING:
    from requests.models import Response


class EncryptionClient:

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.mode = AES.MODE_CBC
        self.ciphertext = None

    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        text = pad(text, 16)
        self.ciphertext = cryptor.encrypt(text)

        return base64.b64encode(self.ciphertext).decode()


class choice(Exchange):

    """ Class for Choice """



    nfo_tokens = {}
    id = 'choice'
    session = Exchange.create_session()

    api_documentation_link = "https://uat.jiffy.in/api/OpenAPI/Info"
    market_data_url = "https://scripmaster-ftp.s3.ap-south-1.amazonaws.com/scripmaster"
    base_url = "https://finx.choiceindia.com/api/OpenAPI"


    token_urls = {
        "login": f"{base_url}/LoginTOTP",
        "totp": f"{base_url}/GetClientLoginTOTP",
        "validate_totp": f"{base_url}/ValidateTOTP",
    }

    urls = {
        "place_order": f"{base_url}/NewOrder",
        "modify_order": f"{base_url}/ModifyOrder",
        "cancel_order": f"{base_url}/CancelOrder",
        "order_history": f"{base_url}/OrderBookByOrderNo",
        "orderbook": f"{base_url}/OrderBook",
        "tradebook": f"{base_url}/TradeBook",

        "positions": f"{base_url}/NetPosition",
        "holdings": f"{base_url}/Holdings",
        "funds": f"{base_url}/FundsView",

        "profile": f"{base_url}/UserProfile",

    }

    req_exchange = {
        ExchangeCode.NSE: 1,
        ExchangeCode.NFO: 2,
        ExchangeCode.BSE: 3,
        "MCX-D": 5,
        "MCX-S": 6,
        "NCDEX-D": 7,
        "NCDEX-S": 8,
        "NCDS-D": 13,
        "NCDS-S": 14
        }

    req_order_type = {
        OrderType.MARKET: "RL_MKT",
        OrderType.LIMIT: "RL_LIMIT",
        OrderType.SL: "SL_LIMIT",
        OrderType.SLM: "SL_MKT"
        }

    req_product = {
        Product.MIS: "M",
        Product.NRML: "D"
        }

    req_side = {
        Side.BUY: 1,
        Side.SELL: 2
        }

    req_validity = {
        Validity.DAY: 1,
        Validity.IOC: 4,
        Validity.GTD: 11,
        Validity.GTC: 11
        }


    resp_exchange = {
        1: ExchangeCode.NSE,
        2: ExchangeCode.NFO,
        3: ExchangeCode.BSE,
        5: "MCX-D",
        6: "MCX-S",
        7: "NCDEX-D",
        8: "NCDEX-S",
        13: "NCDS-D",
        14: "NCDS-S",
        }

    resp_order_type = {
        '2': OrderType.MARKET,
        }

    resp_product = {
        "M": Product.MIS,
        "D": Product.NRML
        }

    resp_side = {
        '1': Side.BUY,
        '2': Side.SELL
        }

    resp_status = {
        "CLIENT XMITTED" : Status.PENDING,
        "GATEWAY XMITTED": Status.PENDING,
        "OMS XMITTED": Status.PENDING,
        "EXCHANGE XMITTED": Status.PENDING,
        "PENDING": Status.PENDING,
        "GATEWAY REJECT": Status.REJECTED,
        "OMS REJECT": Status.REJECTED,
        "ORDER ERROR": Status.REJECTED,
        "FROZEN" : Status.REJECTED,
        "CANCELLED": Status.CANCELLED,
        "AMO CANCELLED" : Status.CANCELLED,
        "AMO SUBMITTED" : Status.OPEN,
        "EXECUTED": Status.FILLED,
        }

    resp_validity = {
        1: Validity.DAY,
        4: Validity.IOC,
        11: f"{Validity.GTD}/{Validity.GTC}",
        }

    @classmethod
    def expiry_markets(cls) -> None:

        try:
            todaysdate = cls.current_datetime()
            weekday = todaysdate.weekday()
            days = 0

            if weekday == 5:
                days = 1
            elif todaysdate.weekday() == 6:
                days = 2

            date_obj = cls.time_delta(todaysdate, days, dtformat="%d%b%Y")
            link = f"{cls.market_data_url}/SCRIP_MASTER_{date_obj}.csv"
            df = cls.data_reader(link, filetype='csv', dtype={"ISIN": str, "SecName": str, 'Instrument': str, "PriceUnit": str, "QtyUnit": str, "DeliveryUnit": str})

            df = df[((df['Symbol'] == 'BANKNIFTY') | (df['Symbol'] == 'NIFTY')) & (df['Instrument'] == 'OPTIDX')]

            df = df[['Token', 'SecDesc', 'Expiry', 'OptionType', 'StrikePrice', 'MarketLot',
                     'MaxOrderLots', 'PriceDivisor', 'Symbol', 'PriceTick'
                     ]]

            df.rename({"Symbol": "Root", "SecDesc": "Symbol", "OptionType": "Option",
                       "PriceTick": "TickSize", "MarketLot": "LotSize",
                       "lastPrice": "LastPrice", "MaxOrderLots": "QtyLimit"},
                      axis=1, inplace=True)

            df['Expiry'] = cls.pd_datetime(df['Expiry']).dt.date.astype(str)
            df['StrikePrice'] = (df['StrikePrice']/df['PriceDivisor']).astype(int)
            df['TickSize'] = df['TickSize']/df['PriceDivisor']

            expiry_data = cls.jsonify_expiry(data_frame=df)

            cls.nfo_tokens = expiry_data

            print("Expiry Data Acquired!!")

        except Exception as exc:
            raise TokenDownloadError({"Error": exc.args}) from exc

    @classmethod
    def create_token(cls,
                     user_name: str,
                     password: str,
                     vendor_id: str,
                     vendor_key: str,
                     encryption_key: str,
                     encryption_iv: str,
                     ) -> dict[str, str]:

        encryption_client = EncryptionClient(encryption_key.encode(), encryption_iv.encode())
        username = encryption_client.encrypt(user_name.encode())
        password = encryption_client.encrypt(password.encode())

        headers = {'VendorId': vendor_id, 'VendorKey': vendor_key, 'Content-Type': 'application/json'}
        json_data = {"UserId": user_name, "Pwd": password}
        response = cls.fetch("POST", cls.token_urls["login"], headers=headers, json=json_data)
        # print(response.text, 'AAAAAAAAAAAAAAAAAA')
        cls.json_parser(response)

        json_data = {"UserId": username}
        response = cls.fetch(method="POST", url=cls.token_urls["totp_url"], headers=headers, json=json_data)
        response = cls.json_parser(response)
        # print(response,'AAAAAAAAA')
        totp = response#['Response']

        json_data = {"UserId": user_name, "Otp": totp}
        response = cls.fetch(method="POST", url=cls.token_urls["validate_totp"], headers=headers, json=json_data)
        response = cls.json_parser(response)

        session_id = response['Response']['SessionId']

        headers = {
            "VendorId": vendor_id,
            "VendorKey": vendor_key,
            "Authorization": f"SessionId {session_id}",
            "Content-Type": "application/json"
            }

        cls.session = cls.create_session()

        return headers

    @classmethod
    def json_parser(cls,
                    response: Response
                    ) -> dict[Any, Any] | list[dict[Any, Any]]:

        json_response = cls.on_json_response(response)
        print(json_response)
        if json_response['Status'] == 'Success':
            return json_response['Response']
        else:
            error = json_response['Reason']
            raise ResponseError(cls.id + " " + error)

    @classmethod
    def orderbook_json_parser(cls, order):

        parsed_order = {
            Order.ID: order['ClientOrderNo'],
            Order.USERID: '',
            Order.TIMESTAMP: cls.datetime_strp(order["Time"], '%Y-%m-%d %H:%M:%S'),
            Order.SYMBOL: order['Symbol'],
            Order.TOKEN: order['Token'],
            Order.SIDE: cls.resp_side[order['BS']],
            Order.TYPE: cls.resp_order_type.get(order['OrderType'], order['OrderType']),
            Order.AVGPRICE: 0.0,
            Order.PRICE: order['Price'],
            Order.TRIGGERPRICE: order['TriggerPrice'],
            Order.TARGETPRICE: order["ProfitOrderPrice"],
            Order.STOPLOSSPRICE: order["SLOrderPrice"],
            Order.TRAILINGSTOPLOSS: order["SLJumpprice"],
            Order.QUANTITY: order['Qty'],
            Order.FILLEDQTY: order['TradedQty'],
            Order.REMAININGQTY:  order['TotalQtyRemaining'],
            Order.CANCELLEDQTY: 0,
            Order.STATUS: cls.resp_status.get(order['OrderStatus'], order['OrderStatus']),
            Order.REJECTREASON: order['ErrorString'],
            Order.DISCLOSEDQUANTITY: order['DisclosedQty'],
            Order.PRODUCT: cls.resp_product.get(order['ProductType'], order['ProductType']),
            Order.EXCHANGE: cls.resp_exchange.get(order['SegmentId'], order['SegmentId']),
            Order.SEGMENT: "",
            Order.VALIDITY: cls.resp_validity.get(order['Validity'], order['Validity']),
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

        # {
        #     'SegmentId': 2,
        #     'Token': 41568,
        #     'Symbol': 'BANKNIFTY',
        #     'ClientOrderNo': 123456,
        #     'OrderType': '2',
        #     'BS': '1',
        #     'Qty': 25,
        #     'DisclosedQty': 0,
        #     'Price': 1319.7,
        #     'TriggerPrice': 0.0,
        #     'Validity': 1,
        #     'ProductType': 'M',
        #     'ExchangeOrderNo': '0',
        #     'ResponseType': 0,
        #     'Remarks': None,
        #     'GatewayOrderNo': '031700004',
        #     'Time': '2023-03-19 18:10:18',
        #     'ErrorString': 'Product Type not allowed for trading for this Instrument Name',
        #     'OrderStatus': 'OMS REJECT',
        #     'SeqNo': 0,
        #     'ExchangeOrderTime': '1363716618',
        #     'TradedQty': 0,
        #     'TotalQtyRemaining': 25,
        #     'LTP': 1625.65,
        #     'InitiatedBy': 'IBT-Ex',
        #     'ModifiedBy': 'IBT-Ex',
        #     'GTDDays': 0,
        #     'GTDStatus': None,
        #     'BracketOrderId': '',
        #     'BracketGatewayOrderId': None,
        #     'SLJumpprice': 0.0,
        #     'LTPJumpPrice': 0.0,
        #     'SLOrderPrice': 0.0,
        #     'SLTriggerPrice': 0.0,
        #     'ProfitOrderPrice': 0.0,
        #     'BracketOrderStatus': '',
        #     'BracketOrderModifyBit': 0,
        #     'LegIndicator': 0
        # }

    @classmethod
    def profile_json_parser(cls,
                            profile: dict
                            ) -> dict[Any, Any]:

        parsed_profile = {
            Profile.CLIENTID: profile['ClientId'],
            Profile.NAME: profile['Name'],
            Profile.EMAILID: profile['EmailID'],
            Profile.MOBILENO: profile['MobileNo'],
            Profile.PAN: "",
            Profile.ADDRESS: "",
            Profile.BANKNAME: "",
            Profile.BANKBRANCHNAME: None,
            Profile.BANKACCNO: "",
            Profile.EXHCNAGESENABLED: [],
            Profile.ENABLED: True,
            Profile.INFO: profile,
            }

        return parsed_profile

    @classmethod
    def create_order_parser(cls,
                            response: Response,
                            headers: dict
                            ) -> dict[Any, Any]:

        info = cls.json_parser(response)

        if 'fault' in info:
            order_id = info['fault']['orderId']
            order = cls.fetch_order(order_id=order_id, headers=headers)
            return order

        if "BSE" not in info['Success']:
            order_id = info['Success']['NSE']['orderId']
            order = cls.fetch_order(order_id=order_id, headers=headers)
            return order

        order_nse = info['Success']['NSE']
        order_bse = info['Success']['BSE']
        data = {
            "NSE": {
                "id": order_nse['orderId'],
                "userOrderId": order_nse['tag'],
                "price": order_nse['orderId'],
                "qauntity": order_nse['quantity'],
                "message": order_nse['message']
                },
            "BSE": {
                "id": order_bse['orderId'],
                "userOrderId": order_bse['tag'],
                "price": order_bse['orderId'],
                "qauntity": order_bse['quantity'],
                "message": order_bse['message']
                },
            "info": info
            }

        return data

    @classmethod
    def market_order(cls,
                     token: int,
                     side: str,
                     quantity: int,
                     exchange: str,
                     headers: dict,
                     symbol: str | None = None,
                     unique_id: str | None = None,
                     product: str = Product.MIS,
                     validity: str = Validity.DAY,
                     ) -> dict[Any, Any]:

        json_data = {
            "SegmentId": cls.req_exchange[exchange],
            "Token": token,
            "OrderType": cls.req_order_type[OrderType.MARKET],
            "BS": cls.req_side[side],
            "Qty": quantity,
            "DisclosedQty": 0,
            "Price": 0,
            "TriggerPrice": 0,
            "Validity": cls.req_validity[validity],
            "ProductType": cls.req_product[product],
            "IsEdisReq": False,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], headers=headers, json=json_data)

        return cls.create_order_parser(response=response,headers=headers)

    @classmethod
    def limit_order(cls,
                    price: float,
                    token: int,
                    side: str,
                    quantity: int,
                    exchange: str,
                    headers: dict,
                    symbol: str | None = None,
                    unique_id: str | None = None,
                    product: str = Product.MIS,
                    validity: str = Validity.DAY
                    ) -> dict[Any, Any]:

        json_data = {
            "SegmentId": cls.req_exchange[exchange],
            "Token": token,
            "OrderType": cls.req_order_type[OrderType.MARKET],
            "BS": cls.req_side[side],
            "Qty": quantity,
            "DisclosedQty": 0,
            "Price": price,
            "TriggerPrice": 0,
            "Validity": cls.req_validity[validity],
            "ProductType": cls.req_product[product],
            "IsEdisReq": False,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], headers=headers, json=json_data)

        return cls.create_order_parser(response=response,headers=headers)

    @classmethod
    def sl_order(cls,
                 price: float,
                 trigger_price: float,
                 token: int,
                 side: str,
                 quantity: int,
                 exchange: str,
                 headers: dict,
                 symbol: str | None = None,
                 unique_id: str | None = None,
                 product: str = Product.MIS,
                 validity: str = Validity.DAY,
                 ) -> dict[Any, Any]:

        json_data = {
            "SegmentId": cls.req_exchange[exchange],
            "Token": token,
            "OrderType": cls.req_order_type[OrderType.MARKET],
            "BS": cls.req_side[side],
            "Qty": quantity,
            "DisclosedQty": 0,
            "Price": price,
            "TriggerPrice": trigger_price,
            "Validity": cls.req_validity[validity],
            "ProductType": cls.req_product[product],
            "IsEdisReq": False,
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], headers=headers, json=json_data)

        return cls.create_order_parser(response=response,headers=headers)

    @classmethod
    def fetch_order(cls,
                    order_id: str,
                    headers: dict,
                    ) -> dict[Any, Any]:

        final_url = f'{cls.urls["order_history"]}/{order_id}'
        response = cls.fetch(method="GET", url=final_url, headers=headers)
        info = cls.json_parser(response)

        detail = info[0]
        order = cls.orderbook_json_parser(detail)

        return order

    @classmethod
    def fetch_orders(cls,
                        headers: dict,
                        ) -> list[dict]:

        response = cls.fetch(method="GET", url=cls.urls["orderbook"], headers=headers)
        info = cls.json_parser(response)

        orders = []
        for order in info['Orders']:
            detail = cls.orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_orderbook(cls,
                        headers: dict,
                        ) -> list[dict]:

        response = cls.fetch(method="GET", url=cls.urls["orderbook"], headers=headers)
        info = cls.json_parser(response)

        orders = []
        for order in info['Orders']:
            detail = cls.orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_tradebook(cls,
                        headers: dict,
                        ) -> list[dict]:

        response = cls.fetch(method="GET", url=cls.urls["tradebook"], headers=headers)
        info = cls.json_parser(response)

        orders = []
        for order in info['Trades']:
            detail = cls.orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def modify_order(cls,
                     order_id: str,
                     headers: dict,
                     price: float | None = None,
                     trigger_price: float | None = None,
                     quantity: int | None = None,
                     ) -> dict[Any, Any]:

        final_url = f"{cls.urls['order_history']}/{order_id}"
        response = cls.fetch(method="GET", url=final_url, headers=headers)
        info = cls.json_parser(response)
        order = info[0]

        json_data = {
            "ClientOrderNo": order['ClientOrderNo'],
            "ExchangeOrderNo": order['ExchangeOrderNo'],
            "GatewayOrderNo": order['GatewayOrderNo'],
            "SegmentId": order['SegmentId'],
            "Token": order['Token'],
            "OrderType": order['OrderType'],
            "BS": order['BS'],
            "DisclosedQty": order['DisclosedQty'],
            "Qty": quantity or order['Qty'],
            "Price": price or order['Price'],
            "TriggerPrice": trigger_price or order['TriggerPrice'],
            "Validity": order['Validity'],
            "ProductType": order['ProductType'],
            }

        response = cls.fetch("POST", cls.urls["modify_order"], headers=headers, json=json_data)

        # return cls.create_order_parser(response=response, headers=headers)
        return cls.json_parser(response)

    @classmethod
    def cancel_order(cls,
                     order_id: str,
                     headers: dict
                     ) -> dict[Any, Any]:

        final_url = f"{cls.urls['order_history']}/{order_id}"
        response = cls.fetch(method="GET", url=final_url, headers=headers)
        info = cls.json_parser(response)
        order = info[0]

        json_data = {
            "ExchangeOrderTime": order["ExchangeOrderTime"],
            "ClientOrderNo": order["ClientOrderNo"],
            "ExchangeOrderNo": order["ExchangeOrderNo"],
            "GatewayOrderNo": order["GatewayOrderNo"],
            "SegmentId": order["SegmentId"],
            "Token": order["Token"],
            "OrderType": order["OrderType"],
            "BS": order["BS"],
            "Qty": order["Qty"],
            "DisclosedQty": order["DisclosedQty"],
            "Price": order["Price"],
            "TriggerPrice": order["TriggerPrice"],
            "Validity": order["Validity"],
            "ProductType": order["ProductType"],
            }

        response = cls.fetch("POST", cls.urls["cancel_order"], headers=headers, json=json_data)

        # return cls.create_order_parser(response=response, headers=headers)
        return cls.json_parser(response)

    @classmethod
    def fetch_holdings(cls,
                   headers: dict,
                   ) -> list[dict]:

        response = cls.fetch(method="GET", url=cls.urls["holdings"], headers=headers)
        return cls.json_parser(response)

    @classmethod
    def fetch_positions(cls,
                   headers: dict,
                   ) -> list[dict]:

        response = cls.fetch(method="GET", url=cls.urls["positions"], headers=headers)
        return cls.json_parser(response)

    @classmethod
    def fetch_funds(cls,
                   headers: dict,
                   ) -> list[dict]:

        response = cls.fetch(method="GET", url=cls.urls["funds"], headers=headers)
        return cls.json_parser(response)

    @classmethod
    def profile(cls,
                   headers: dict,
                   ) -> list[dict]:

        response = cls.fetch(method="GET", url=cls.urls["profile"], headers=headers)
        info = cls.json_parser(response)

        return cls.profile_json_parser(info)
