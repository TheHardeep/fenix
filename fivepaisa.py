from __future__ import annotations
from typing import TYPE_CHECKING
from typing import Any
import base64
from re import split as ReSplit
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

from kronos.base.exchange import Exchange

from kronos.base.constants import Side
from kronos.base.constants import OrderType
from kronos.base.constants import ExchangeCode
from kronos.base.constants import Product
from kronos.base.constants import Validity
from kronos.base.constants import Status
from kronos.base.constants import Order
from kronos.base.constants import Position
from kronos.base.constants import Root


from kronos.base.errors import InputError
from kronos.base.errors import TokenDownloadError

if TYPE_CHECKING:
    from requests.models import Response


class EncryptionClient:

    def __init__(self, encryption_key):

        self.iv = bytes([83, 71, 26, 58, 54, 35, 22, 11,
                        83, 71, 26, 58, 54, 35, 22, 11])
        self.enc_key = encryption_key

    def _pad_and_convert_to_bytes(self, text):
        return bytes(text + chr(16 - len(text) % 16) * (16 - len(text) % 16), encoding="utf-8")

    def encrypt(self, text):
        padded_text = self._pad_and_convert_to_bytes(text)
        cd = PBKDF2(password=self.enc_key, salt=self.iv, dkLen=48)
        aesiv = cd[:16]
        aeskey = cd[16:]

        cipher = AES.new(aeskey, AES.MODE_CBC, aesiv)

        return str(base64.b64encode(cipher.encrypt(padded_text)), encoding="utf-8")


class fivepaisa(Exchange):

    """ Class for 5Paisa """

    nfo_tokens = {}
    id = "fivepaisa"
    _session = Exchange._create_session()

    base_urls = {
        "api_documentation_link": "https://www.5paisa.com/developerapi/overview",
        "market_data_url": "https://images.5paisa.com/website/scripmaster-csv-format.csv",
        "base_url": "https://Openapi.5paisa.com/VendorsAPI/Service1.svc",
        "access_token_url": "https://Openapi.5paisa.com/VendorsAPI/Service1.svc/V4/LoginRequestMobileNewbyEmail",
    }

    urls = {
        "place_order": f"{base_urls['base_url']}/V1/PlaceOrderRequest",
        "bo_order": f"{base_urls['base_url']}/SMOOrderRequest",
        "modify_order": f"{base_urls['base_url']}/V1/ModifyOrderRequest",
        "cancel_order": f"{base_urls['base_url']}/V1/CancelOrderRequest",
        "orderbook": f"{base_urls['base_url']}/V2/OrderBook",
        "tradebook": f"{base_urls['base_url']}/V1/TradeBook",
        "positions": f"{base_urls['base_url']}/V4/NetPosition",
        "holdings": f"{base_urls['base_url']}/V3/Holding",
    }



    req_exchange = {
        ExchangeCode.NSE: "N",
        ExchangeCode.NFO: "N",
        ExchangeCode.BSE: "B",
        ExchangeCode.BFO: "B"
    }

    req_exchange_type = {
        ExchangeCode.NSE: "C",
        ExchangeCode.NFO: "D",
        ExchangeCode.BSE: "C",
        ExchangeCode.BFO: "D"
    }

    req_product = {
        Product.MIS: True,
        Product.NRML: False
    }

    req_side = {
        Side.BUY: "Buy",
        Side.SELL: "Sell"
    }

    req_validity = {
        Validity.DAY: False,
        Validity.IOC: True
    }



    resp_exchange = {
        "N": ExchangeCode.NSE,
        "B": ExchangeCode.BSE,
        "M": ExchangeCode.MCX
    }

    resp_order_type = {
        "N": OrderType.LIMIT,
        "Y": OrderType.MARKET,
    }

    resp_product = {
        "I": Validity.DAY,
        "D": Product.NRML
    }

    resp_side = {
        "B": Side.BUY,
        "S": Side.SELL
    }

    resp_segment = {
        "NC": ExchangeCode.NSE,
        "ND": ExchangeCode.NFO,
        "NU": "NU",
        "BC": ExchangeCode.BSE,
        "BD": ExchangeCode.BFO,
        "BU": "BU",
        "MC": "MSE",
        "MD": "MFO",
        "MU": "MU"
    }

    resp_validity = {
        0: Validity.DAY,
        1: Validity.GTD,
        2: Validity.GTC,
        3: Validity.IOC,
        4: "EOS",
        5: "VTD",
        6: Validity.FOK,
    }

    resp_status = {
        "Fully Executed": Status.FILLED,
        "Rejected By 5P": Status.REJECTED,
        'Pending': Status.PENDING,
        "Cancelled": Status.CANCELLED,
        "modified": Status.MODIFIED,
    }



    @classmethod
    def create_indices(cls) -> dict:
        """
        Gives NFO Indices Info for F&O Segment.

        Returns:
            dict: Unified kronos create_nfo_tokens format
        """

        df = cls.data_reader(cls.base_urls["market_data_url"], filetype='csv')

        df = df[(df['CpType'] == "EQ")][["Name", "Scripcode"]]
        df.rename({"Name": "Symbol", "Scripcode": "Token"}, axis=1, inplace=True)
        df.index = df['Symbol']

        indices = df.to_dict(orient='index')

        indices[Root.BNF] = indices["BANKNIFTY"]
        indices[Root.NF] = indices["NIFTY"]
        indices[Root.FNF] = indices["FINNIFTY"]
        indices[Root.MIDCPNF] = indices["MIDCPNifty"]

        cls.indices = indices

        return indices

    @classmethod
    def create_nfo_tokens(cls):

        try:

            df = cls.data_reader(cls.base_urls["market_data_url"], filetype='csv')

            df = df[['Exch', 'ExchType', 'Scripcode', 'Name', 'CpType',
                     'StrikeRate', 'LotSize', 'QtyLimit', 'Underlyer', 'Root', 'TickSize'
                     ]]

            df = df[
                (
                    (df['Root'] == 'NIFTY') |
                    (df['Root'] == 'BANKNIFTY') |
                    (df['Root'] == "FINNIFTY") |
                    (df['Root'] == "MIDCPNIFTY")
                ) &
                (
                    (df['CpType'].str.endswith("E"))
                )]


            df.rename({"StrikeRate": "StrikePrice", "Scripcode": "Token",
                       "Name": "Symbol", "CpType": "Option", "Underlyer": "Expiry"},
                      axis=1, inplace=True)

            df['Expiry'] = cls.pd_datetime(df['Expiry']).dt.date.astype(str)
            df['StrikePrice'] = df['StrikePrice'].astype(int)

            expiry_data = cls.jsonify_expiry(data_frame=df)

            cls.nfo_tokens = expiry_data

            return expiry_data

        except Exception as exc:
            raise TokenDownloadError({"Error": exc.args}) from exc



    @classmethod
    def create_headers(cls,
                       params: dict,
                       ) -> dict[str, str]:

        """_summary_

        Raises:
            KeyError: _description_

        Returns:
            _type_: _description_
        """


        for key in ["user_id", "password", "email", "web_login_password",
                    "dob", "app_name", "user_key", "encryption_key"]:

            if key not in params:
                raise KeyError(f"Please provide {key}")


        encryption_client = EncryptionClient(params["encryption_key"])

        login_payload = {
            "head": {
                "appName": params["app_name"],
                "appVer": "1.0",
                "key": params["user_key"],
                "osName": "WEB",
                "requestCode": "5PLoginV4",
                "userId": params["user_id"],
                "password": params["password"],
            },
            "body": {
                "Email_id": encryption_client.encrypt(params["email"]),
                "Password": encryption_client.encrypt(params["web_login_password"]),
                "LocalIP": "0.0.0.0",
                "PublicIP": "0.0.0.0",
                "HDSerailNumber": "",
                "MACAddress": "",
                "MachineID": "000000",
                "VersionNo": "1.7",
                "RequestNo": "1",
                "My2PIN": encryption_client.encrypt(params["dob"]),
                "ConnectionType": "1"
            }
        }

        print(login_payload)

        response = cls.fetch(method="POST", url=cls.base_urls["access_token_url"], json=login_payload)
        response = cls.json_parser(response)

        client_code = response['body']["ClientCode"]
        jwt_token = response['body']['JWTToken']
        print(response)
        req_headers = {
            "Content-Type": "application/json",
            "Authorization": f"bearer {jwt_token}"
        }

        json_data = {
            "head": {
                "key": params["user_key"],
            },
            "body": {
                "ClientCode": client_code,
            }
        }

        headers = {
            "headers": req_headers,
            "user_key": params["user_key"],
            "client_code": client_code,
            "json_data": json_data,
        }

        cls._session = cls._create_session()

        return headers

    @classmethod
    def datetime_converter(cls,
                           dt_str: str
                           ):

        """
        dt: str '/Date(1674102081443+0530)/'
        """

        dt_str = int(ReSplit(r'\(|\+', dt_str)[1])
        return cls.from_timestamp(dt_str / 1000)

    @classmethod
    def json_parser(cls,
                    response: Response
                    ) -> dict[Any, Any] | list[dict[Any, Any]]:

        json_response = cls.on_json_response(response)
        print(json_response)

        return json_response

    @classmethod
    def orderbook_json_parser(cls,
                              order: dict
                              ) -> dict[Any, Any]:

        parsed_order = {
            Order.ID: order['ExchOrderID'],
            Order.USERID: order['RemoteOrderID'],
            Order.TIMESTAMP: cls.datetime_converter(order['ExchOrderTime']),
            Order.SYMBOL: order['ScripName'],
            Order.TOKEN: order['ScripCode'],
            Order.SIDE: cls.resp_side[order['BuySell']],
            Order.TYPE: "SL" if order['WithSL'] == "Y" else cls.resp_order_type[order['AtMarket']],
            Order.AVGPRICE: order['Rate'],  # float(order['Rate'] or 0.0),
            Order.PRICE: order['Rate'],  # float(order['Rate'] or 0.0),
            Order.TRIGGERPRICE: order['SLTriggerRate'],  # float(order['SLTriggerRate'] or 0.0),
            Order.QUANTITY: order['Qty'],
            Order.FILLEDQTY: order['TradedQty'],
            Order.REMAININGQTY: order['PendingQty'],
            Order.CANCELLEDQTY: 0,
            Order.STATUS: cls.resp_status.get(order['OrderStatus'], order['OrderStatus']),
            Order.REJECTREASON: order['Reason'],
            Order.DISCLOSEDQUANTITY: order['DisClosedQty'],
            Order.PRODUCT: cls.resp_product[order['DelvIntra']],
            Order.EXCHANGE: cls.resp_exchange[order['Exch']],
            Order.SEGMENT: cls.resp_segment[order['Exch'] + order['ExchType']],
            Order.VALIDITY: cls.resp_validity[order['OrderValidity']],
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

        # {
        #     'AHProcess': 'N',
        #     'AfterHours': 'N',
        #     'AtMarket': 'N',
        #     'BrokerOrderId': 48429332,
        #     'BrokerOrderTime': '/Date(1679479428997+0530)/',
        #     'BuySell': 'B',
        #     'DelvIntra': 'D',
        #     'DisClosedQty': 0,
        #     'Exch': 'N',
        #     'ExchOrderID': '1800000091470711',
        #     'ExchOrderTime': '/Date(1679471618000+0530)/',
        #     'ExchType': 'D',
        #     'MarketLot': 2,
        #     'OldorderQty': 0,
        #     'OrderRequesterCode': '58921440       ',
        #     'OrderStatus': 'Cancelled',
        #     'OrderValidUpto': '22 Mar 2023',
        #     'OrderValidity': 0,
        #     'PendingQty': 50,
        #     'Qty': 50,
        #     'Rate': 8.25,
        #     'Reason': '',
        #     'RemoteOrderID': '',
        #     'RequestType': 'C',
        #     'SLTriggerRate': 7.5,
        #     'SLTriggered': 'N',
        #     'SMOProfitRate': 0,
        #     'SMOSLLimitRate': 0,
        #     'SMOSLTriggerRate': 0,
        #     'SMOTrailingSL': 0,
        #     'ScripCode': 41542,
        #     'ScripName': 'BANKNIFTY 23 Mar 2023 PE 37500.00',
        #     'TerminalId': 46189,
        #     'TradedQty': 0,
        #     'WithSL': 'Y'
        # }

    @classmethod
    def tradebook_json_parser(cls,
                              order: dict
                              ) -> dict[Any, Any]:

        parsed_order = {
            Order.ID: order['ExchOrderID'],
            Order.USERID: "",
            Order.TIMESTAMP: cls.datetime_converter(order['ExchangeTradeTime']),
            Order.SYMBOL: order['ScripName'],
            Order.TOKEN: order['ScripCode'],
            Order.SIDE: cls.resp_side[order['BuySell']],
            Order.TYPE: "",
            Order.AVGPRICE: float(order['Rate'] or 0.0),
            Order.PRICE: 0.0,
            Order.TRIGGERPRICE: 0.0,
            Order.QUANTITY: order['Qty'],
            Order.FILLEDQTY: order['Qty'] - order['PendingQty'],
            Order.REMAININGQTY: order['PendingQty'],
            Order.CANCELLEDQTY: 0,
            Order.STATUS: "",
            Order.REJECTREASON: "",
            Order.DISCLOSEDQUANTITY: 0,
            Order.PRODUCT: cls.resp_product[order['DelvIntra']],
            Order.EXCHANGE: cls.resp_exchange[order['Exch']],
            Order.SEGMENT: cls.resp_segment[order['Exch'] + order['ExchType']],
            Order.VALIDITY: "",
            Order.VARIETY: "",
            Order.INFO: order,
        }

        return parsed_order

    @classmethod
    def position_json_parser(cls,
                             position: dict,
                             ) -> dict[Any, Any]:

        parsed_position = {
            Position.SYMBOL: position["ScripName"],
            Position.TOKEN: position["ScripCode"],
            Position.NETQTY: position["NetQty"],
            Position.AVGPRICE: (position["BuyValue"] + position["SellValue"]) / (position["BuyQty"] + position["SellQty"]),
            Position.MTM: position["MTOM"],
            Position.PNL: position["BookedPL"],
            Position.BUYQTY: position["BuyQty"],
            Position.BUYPRICE: position["BuyAvgRate"],
            Position.SELLQTY: position["SellQty"],
            Position.SELLPRICE: position["SellAvgRate"],
            Position.LTP: position["LTP"],
            Position.PRODUCT: cls.resp_product.get(position["OrderFor"], position["OrderFor"]),
            Position.EXCHANGE: cls.resp_segment[position['Exch'] + position['ExchType']],
            Position.INFO: position,
        }

        return parsed_position

    @classmethod
    def create_order_parser(cls,
                            response: Response,
                            headers: dict
                            ) -> dict[Any, Any]:

        info = cls.json_parser(response)

        broker_id = info['body']['BrokerOrderID']
        order = cls.fetch_order(order_id=broker_id, headers=headers, key_to_check="BrokerOrderId")

        return order

        # {
        #     'body': {
        #         'BrokerOrderID': 0,
        #         'ClientCode': '58921440',
        #         'Exch': 'N',
        #         'ExchOrderID': '0',
        #         'ExchType': 'D',
        #         'LocalOrderID': 0,
        #         'Message': 'Kindly place limit order, please place again.',
        #         'RMSResponseCode': -1,
        #         'RemoteOrderID': 'MarketOrder',
        #         'ScripCode': 141633,
        #         'Status': 1,
        #         'Time': '/Date(1679423400000+0530)/'
        #         },
        #     'head': {
        #         'responseCode': '5PPlaceOrdReqV1',
        #         'status': '0',
        #         'statusDescription': 'Success'
        #         }
        # }




    @classmethod
    def market_order(cls,
                     symbol: str,
                     token: int,
                     side: str,
                     unique_id: str,
                     quantity: int,
                     exchange: str,
                     headers: dict,
                     product: str = Product.MIS,
                     validity: str = Validity.DAY,
                     ) -> dict[Any, Any]:

        json_data = {
            'head': {
                'key': headers["user_key"],
            },
            'body': {
                'DisQty': 0,
                'Exchange': cls.req_exchange[exchange],
                'ExchangeType': cls.req_exchange_type[exchange],
                'IsIntraday': cls.req_product[product],
                'Price': 0,
                'StopLossPrice': 0,
                'Qty': quantity,
                'IsIOCOrder': cls.req_validity[validity],
                'ScripCode': token,
                'OrderType': cls.req_side[side],
                'RemoteOrderID': unique_id,
                'IsStopLossOrder': False,
                'IsAHOrder': 'N',
                'ClientCode': headers["client_code"],
            }
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

        return cls.create_order_parser(response=response, headers=headers)

    @classmethod
    def limit_order(cls,
                    price: float,
                    symbol: str,
                    token: int,
                    side: str,
                    unique_id: str,
                    quantity: int,
                    exchange: str,
                    headers: dict,
                    product: str = Product.MIS,
                    validity: str = Validity.DAY,
                    ) -> dict[Any, Any]:

        json_data = {
            'head': {
                'key': headers["user_key"],
            },
            'body': {
                'DisQty': 0,
                'Exchange': cls.req_exchange[exchange],
                'ExchangeType': cls.req_exchange_type[exchange],
                'IsIntraday': cls.req_product[product],
                'Price': price,
                'StopLossPrice': 0,
                'Qty': quantity,
                'IsIOCOrder': cls.req_validity[validity],
                'ScripCode': token,
                'OrderType': cls.req_side[side],
                'RemoteOrderID': unique_id,
                'IsStopLossOrder': False,
                'IsAHOrder': 'N',
                'ClientCode': headers["client_code"],
            }
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

        return cls.create_order_parser(response=response, headers=headers)

    @classmethod
    def sl_order(cls,
                 price: float,
                 trigger_price: float,
                 symbol: str,
                 token: int,
                 side: str,
                 unique_id: str,
                 quantity: int,
                 exchange: str,
                 headers: dict,
                 product: str = Product.MIS,
                 validity: str = Validity.DAY,
                 ) -> dict[Any, Any]:

        json_data = {
            'head': {
                'key': headers["user_key"],
            },
            'body': {
                'DisQty': 0,
                'Exchange': cls.req_exchange[exchange],
                'ExchangeType': cls.req_exchange_type[exchange],
                'IsIntraday': cls.req_product[product],
                'Price': price,
                'StopLossPrice': trigger_price,
                'Qty': quantity,
                'IsIOCOrder': cls.req_validity[validity],
                'ScripCode': token,
                'OrderType': cls.req_side[side],
                'RemoteOrderID': unique_id,
                'IsStopLossOrder': True,
                'IsAHOrder': 'N',
                'ClientCode': headers["client_code"],
            }
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

        return cls.create_order_parser(response=response, headers=headers)



    @classmethod
    def market_order_bo(cls,
                        symbol: str,
                        token: int,
                        side: str,
                        unique_id: str,
                        quantity: int,
                        exchange: str,
                        headers: dict,
                        target: float = 0,
                        stoploss: float = 0,
                        trailing_sl: float = 0,
                        product: str = Product.MIS,
                        validity: str = Validity.DAY,
                        ) -> dict[Any, Any]:

        json_data = {
            'head': {
                'key': headers["user_key"],
            },
            'body': {
                "DisQty": "0",
                "Exch": cls.req_exchange[exchange],
                "ExchType": cls.req_exchange_type[exchange],
                "AtMarket": True,
                "LimitPriceInitialOrder": "0.0",
                "TriggerPriceInitialOrder": "0.0",
                "LimitPriceProfitOrder": target,
                "StopLoss": stoploss,
                "TrailingSL": trailing_sl,
                "Qty": quantity,
                "ScripCode": token,
                "BuySell": cls.req_side[side],
                "UniqueOrderIDNormal": unique_id,
                "ClientCode": headers["client_code"],
                "OrderRequesterCode": headers["client_code"],
                "RequestType": "P",
                "LimitPriceForSL": "0.0",
                "TriggerPriceForSL": "0.0",
                "OrderFor": "C",
                "UniqueOrderIDSL": "0",
                "UniqueOrderIDLimit": "0",
                "LocalOrderIDNormal": "0",
                "LocalOrderIDSL": "0",
                "LocalOrderIDLimit": "0",
                "TradedQty": "0",
            }
        }

        response = cls.fetch(method="POST", url=cls.urls["place_order"], json=json_data, headers=headers["headers"])

        return cls.create_order_parser(response=response, headers=headers)




    @classmethod
    def fetch_order(cls,
                    order_id: str,
                    headers: dict,
                    key_to_check: str = "ExchOrderID",
                    ) -> dict[Any, Any]:

        orderid = str(order_id) if key_to_check == "ExchOrderID" else int(order_id)

        response = cls.fetch(method="POST", url=cls.urls["orderbook"], json=headers["json_data"], headers=headers["headers"])
        info = cls.json_parser(response)

        for order in info['body']['OrderBookDetail']:
            if order[key_to_check] == orderid:
                detail = cls.orderbook_json_parser(order)
                detail['avgPrice'] = cls.fetch_tradebook_order(order_id=detail['id'], headers=headers, default=False)  # Five Paisa API is Fuddu i.e. commented.
                return detail

        raise InputError({"This orderid does not exist."})

    @classmethod
    def fetch_orders(cls,
                     headers: dict
                     ) -> list[dict]:

        response = cls.fetch(method="POST", url=cls.urls["orderbook"], json=headers["json_data"], headers=headers['headers'])
        info = cls.json_parser(response)

        tradebook_orders = cls.fetch_tradebook(headers=headers, default=False)

        orders = []
        for order in info['body']['OrderBookDetail']:
            detail = cls.orderbook_json_parser(order)

            avgprice = tradebook_orders[detail['id']]['avgPrice'] if tradebook_orders.get(detail['id']) else 0.0
            detail['avgPrice'] = avgprice

            orders.append(detail)

        return orders

    @classmethod
    def fetch_orderbook(cls,
                        headers: dict,
                        ) -> list[dict]:

        response = cls.fetch(method="POST", url=cls.urls["orderbook"], json=headers["json_data"], headers=headers['headers'])
        info = cls.json_parser(response)

        orders = []
        for order in info['body']['OrderBookDetail']:
            detail = cls.orderbook_json_parser(order)
            orders.append(detail)

        return orders

    @classmethod
    def fetch_tradebook(cls,
                        headers: dict,
                        default: bool = True,
                        ) -> list[dict] | dict[Any, Any]:

        response = cls.fetch(method="POST", url=cls.urls["tradebook"], json=headers["json_data"], headers=headers["headers"])
        info = cls.json_parser(response)

        if default:
            orders = []
            for order in info['body']['TradeBookDetail']:
                detail = cls.tradebook_json_parser(order)
                orders.append(detail)
            return orders

        orders = {}
        for order in info['body']['TradeBookDetail']:
            detail = cls.tradebook_json_parser(order)
            orders[detail['id']] = detail

        return orders

    @classmethod
    def fetch_tradebook_order(cls,
                              order_id: str,
                              headers: dict,
                              default: bool = True,
                              ):


        response = cls.fetch(method="POST", url=cls.urls["tradebook"], json=headers["json_data"], headers=headers["headers"])
        info = cls.json_parser(response)

        orders = []
        for order in info['body']['TradeBookDetail']:
            if order["ExchOrderID"] == order_id:
                if default:
                    detail = cls.tradebook_json_parser(order)
                    return detail

                return order['Rate']

        if default:
            return orders

        return 0.0



    @classmethod
    def modify_order(cls,
                     order_id: str,
                     headers: dict,
                     price: float | None = None,
                     trigger_price: float | None = None,
                     quantity: int | None = None,
                     order_type: str | None = None,
                     validity: str | None = None,
                     ) -> dict[Any, Any]:


        response = cls.fetch(method="POST", url=cls.urls["orderbook"], json=headers["json_data"], headers=headers["headers"])
        info = cls.json_parser(response)

        order = {}
        for order_det in info['body']['OrderBookDetail']:
            if order_det["ExchOrderID"] == order_id:
                order = order_det
                break

        if not order:
            raise InputError({"This orderid does not exist."})

        json_data = {
            'head': {
                'key': headers['user_key'],
            },
            'body': {
                "Price": price or order['Rate'],
                "Qty": quantity or order['Qty'],
                "ExchOrderID": order['ExchOrderID'],
                "DisQty": order['DisClosedQty'],
                "Stoplossprice": trigger_price or order['SLTriggerRate'],
                "RemoteOrderID": order['RemoteOrderID'],
            }
        }

        response = cls.fetch(method="POST", url=cls.urls["modify_order"], json=json_data, headers=headers["headers"])
        response = cls.json_parser(response)

        return cls.fetch_order(order_id=order_id, headers=headers)

    @classmethod
    def cancel_order(cls,
                     order_id: str,
                     headers: dict
                     ) -> dict[Any, Any]:

        json_data = {
            'head': {
                'key': headers['user_key'],
            },
            'body': {
                'ExchOrderID': order_id,
            }
        }

        response = cls.fetch(method="POST", url=cls.order_cancel_url, headers=headers["headers"], json=json_data)
        info = cls.json_parser(response)

        order_id = info['body']['ExchOrderID']
        order = cls.fetch_order(order_id=order_id, headers=headers)

        return order



    @classmethod
    def fetch_positions(cls,
                        headers: dict,
                        ) -> list[dict]:

        response = cls.fetch(method="POST", url=cls.urls["positions"], json=headers["json_data"], headers=headers["headers"])
        info = cls.json_parser(response)

        positions = []
        for position in info['head']['NetPositionDetail']:
            detail = cls.position_json_parser(position)
            positions.append(detail)

        return positions


    @classmethod
    def fetch_holdings(cls,
                       headers: dict,
                       ) -> list[dict]:

        response = cls.fetch(method="POST", url=cls.urls["holdings"],
                             json=headers["json_data"], headers=headers["headers"])
        info = cls.json_parser(response)

        return info

        # {'body': {'CacheTime': 300,
        #     'Data': [{'AvgRate': 2059.8125,
        #         'BseCode': 543396,
        #         'CurrentPrice': 624.05,
        #         'DPQty': 80,
        #         'Exch': '\x00',
        #         'ExchType': 'C',
        #         'FullName': 'ONE 97 COMMUNICATIONS LTD',
        #         'NseCode': 6705,
        #         'POASigned': 'N',
        #         'PoolQty': 0,
        #         'Quantity': 80,
        #         'ScripMultiplier': 1,
        #         'Symbol': 'PAYTM'},
        #     {'AvgRate': 22.63,
        #         'BseCode': 540787,
        #         'CurrentPrice': 58.73,
        #         'DPQty': 1,
        #         'Exch': '\x00',
        #         'ExchType': 'C',
        #         'FullName': 'ICICIPRAMC - BHARATIWIN',
        #         'NseCode': 522,
        #         'POASigned': 'N',
        #         'PoolQty': 0,
        #         'Quantity': 1,
        #         'ScripMultiplier': 1,
        #         'Symbol': 'ICICIB22'}],
        #     'Message': 'Success',
        #     'Status': 0},
        #     'head': {'responseCode': '5PHoldingV3',
        #     'status': '0',
        #     'statusDescription': 'Success'}}
