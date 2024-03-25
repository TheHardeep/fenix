from __future__ import annotations
from datetime import datetime
from datetime import timedelta
from os import popen
from json import dumps
from json import loads
from ssl import SSLError
from time import sleep
from typing import Any
from pandas import DataFrame
from pandas import read_csv
from pandas import read_json
from pandas import to_datetime
from pandas import concat
from pandas.tseries.offsets import DateOffset
from pandas import options
from numpy import nan
from pyotp import TOTP

from re import compile


from requests.sessions import session as req_session
from requests.models import Response
from requests.exceptions import HTTPError
from requests.exceptions import Timeout
from requests.exceptions import TooManyRedirects
from requests.exceptions import RequestException
from requests.exceptions import ConnectionError as requestsConnectionError

from fenix.base.constants import Root
from fenix.base.constants import WeeklyExpiry

from fenix.base.errors import InputError
from fenix.base.errors import ResponseError
from fenix.base.errors import RequestTimeout
from fenix.base.errors import NetworkError
from fenix.base.errors import BrokerError

options.mode.chained_assignment = None


__all__ = [
    'Broker',
]


class Broker:

    """ Base Class Common to All Brokers """

    id = ''
    indices = {}
    eq_tokens = {}
    nfo_tokens = {}
    expiry_dates = {}
    cookies = {}
    _session = None

    nfo_url = "https://www.nseindia.com/api/option-chain-indices"
    bfo_url = "https://api.bseindia.com/BseIndiaAPI/api/ddlExpiry_IV/w"

    def __repr__(self):
        return f"fenix.{self.id}()"

    @staticmethod
    def _create_session():
        """
        Creates A request Session.

        Returns:
            requests.sessions.session: returns a reqeusts.sessions.session Object
        """
        return req_session()

    @classmethod
    def fetch(cls,
              method: str,
              url: str,
              headers: dict[Any, Any] | None = None,
              data: dict[Any, Any] | None = None,
              json: dict[Any, Any] | None = None,
              params: dict[Any, Any] | None = None,
              auth: tuple[str, str] | None = None,
              timeout: int = 10,
              ) -> Response:
        """
        A Wrapper for Python Requests module,
        sending requests over a session which persists the cookies over the entire session.

        Parameters:
            method (str): Request Method: 'GET', 'POST', 'PUT', 'DELETE', 'GET', etc.
            url (str): URL of the Request
            headers (dict[Any, Any] | None, optional): Request Headers. Defaults to None.
            data (dict[Any, Any] | None, optional): Dictionary, list of tuples, bytes, or file-like object to send in the body of the Request. Defaults to None.
            json (dict[Any, Any] | None, optional): A JSON serializable Python object to send in the body of the Request. Defaults to None.
            params (dict[Any, Any] | None, optional): Dictionary, list of tuples or bytes to send in the query string for the Request. Defaults to None.
            auth (tuple[str, str] | None, optional): Auth tuple to enable Basic/Digest/Custom HTTP Auth. Defaults to None.
            timeout (int, optional): How many seconds to wait for the server to send data before giving up. Defaults to 10.

        Raises:
            RequestTimeout: If the Request Times Out
            NetworkError: If Network Unavailable.
            BrokerError: If Error on Behalf of the Broker or Some Error on behalf of the User sending the Request.

        Returns:
            Response: Response Object
        """

        try:
            response = cls._session.request(method=method,
                                            url=url,
                                            headers=headers,
                                            data=data,
                                            json=json,
                                            params=params,
                                            auth=auth,
                                            timeout=timeout,
                                            )

            response.raise_for_status()

            return response

        except Timeout as exc:
            details = ' '.join([cls.id, method, url])
            raise RequestTimeout(details) from exc

        except TooManyRedirects as exc:
            details = ' '.join([cls.id, method, url])
            raise BrokerError(details) from exc

        except SSLError as exc:
            details = ' '.join([cls.id, method, url])
            raise BrokerError(details) from exc

        except HTTPError as exc:
            details = ' '.join([cls.id, method, str(response.status_code), url, response.text])
            raise BrokerError(details) from exc

        except requestsConnectionError as exc:
            error_string = str(exc)
            details = ' '.join([cls.id, method, url, error_string])
            if 'Read timed out' in error_string:
                raise RequestTimeout(details) from exc
            raise NetworkError(details) from exc

        except ConnectionResetError as exc:
            details = ' '.join([cls.id, method, url])
            raise NetworkError(details) from exc

        except RequestException as exc:  # base exception class
            error_string = str(exc)
            details = ' '.join([cls.id, method, url])
            if any(x in error_string for x in ['ECONNRESET', 'Connection aborted.', 'Connection broken:']):
                raise NetworkError(exc) from exc
            raise BrokerError(exc) from exc

    @staticmethod
    def _json_parser(response: Response) -> dict[Any, Any] | list[dict[Any, Any]]:
        """
        Get json object from a request Response.

        Parameters:
            response (Response): Response Object

        Returns:
            dict: Json Object received from Response.
        """
        try:
            response = loads(response.text.strip())
            # print(response)
            return response
        except Exception as exc:
            raise ResponseError({"Status": response.status_code,
                                 "Error": response.text,
                                 "URL": response.url,
                                 "Reason": response.reason
                                 }
                                ) from exc

    @staticmethod
    def json_dumps(json_data: dict) -> str:
        return dumps(json_data)

    @staticmethod
    def on_json_response(response: Response) -> dict[Any, Any]:
        """
        Get json object from a request Response.

        Parameters:
            response (Response): Response Object

        Returns:
            dict: Json Object received from Response.
        """
        # print(response.text)
        return loads(response.text.strip())


    @staticmethod
    def _eq_mapper(dictionary: dict, key: str) -> str:
        """
        A Simple Function to help the User if they input a wrong Symbol in the eq_tokens dictionary,
        also tells the User the possible Symbols for the Segment.

        Parameters:
            dictionary (dict): Dicitonary
            key (str): Dictionary Key to Check Against, should be capital Letters.

        Raises:
            KeyError: If Key Does not exist in the Dicitonary.

        Returns:
            str: The Value of the Key in the Dicitonary.
        """
        key = key.upper()
        if key in dictionary:
            return dictionary[key]

        r = compile(r"[A-Z]*<str>[A-Z]*$".replace("<str>", key))
        possible_values = list(filter(r.findall, dictionary))

        raise KeyError(f"Invalid Symbol!: {key}, Possible Values: {possible_values}")


    @staticmethod
    def _key_mapper(dictionary: dict, key: str, name: str) -> str:
        """
        A Simple Function to help the User if they input a wrong Key in the Dictionary,
        also tells the User the possible Keys for the Dicitonary.

        Parameters:
            dictionary (dict): Dicitonary
            key (str): Dictionary Key to Check Against.
            name (str): The right Key to the Dicitonary.

        Raises:
            KeyError: If Key Does not exist in the Dicitonary.

        Returns:
            str: The Value of the Key in the Dicitonary.
        """

        if key in dictionary:
            return dictionary[key]

        raise KeyError(f"Invalid {name}!: {key}, Possible Values: {list(dictionary.keys())}")

    @staticmethod
    def totp_creator(totpbase: str) -> str:
        """
        Get TOTP from the character string.

        Parameters:
            totpbase (str): String used to Generate TOTP.

        Returns:
            str: Six-Digit TOTP
        """
        while True:
            totpobj = TOTP(totpbase)
            totp = totpobj.now()

            if totpobj.verify(totp):
                return totp


    @staticmethod
    def data_reader(link: str,
                    filetype: str,
                    dtype: dict | None = None,
                    sep: str = ",",
                    col_names: list = [],
                    ) -> DataFrame:
        """
        Pandas.read_csv & Pandas.read_json Functions Wrapper

        Parameters:
            link (str): URL to get the Data From.
            filetype (str): 'json' | 'csv'
            dtype (dict | None, optional): A Dicitonary with Column-Names as the Keys and their Datatypes as the values. Defaults to None.
            sep (str, optional): Needed with filetype as 'csv', to input the data seperator. Defaults to ','.

        Raises:
            InputError: If Wrong filetype Given as Input

        Returns:
            DataFrame: Pandas DataFrame
        """
        if filetype == "json":
            return read_json(link)

        if filetype == "csv":
            if col_names:
                return read_csv(link,
                                dtype=dtype,
                                sep=sep,
                                names=col_names,
                                )

            return read_csv(link,
                            dtype=dtype,
                            sep=sep
                            )


        raise InputError(f"Wrong Filetype: {filetype}, the possible values are: 'json', 'csv'")

    @staticmethod
    def data_frame(data: list) -> DataFrame:
        """
        Pandas.DataFrame Function Wrapper

        Parameters:
            data (list): List of Data to make the DataFrame out of.

        Returns:
            DataFrame: Pandas DataFrame
        """
        return DataFrame(data)


    @staticmethod
    def pd_datetime(datetime_obj: str,
                    unit: str = "ns"
                    ) -> datetime:
        """
        Pandas.to_datetime Function Wrapper

        Parameters:
            datetime_obj (str): Datetime String to convert to datetime object.
            unit (str, optional): The unit of the datetime_obj (D,s,ms,us,ns) denote the unit. Defaults to "ns".

        Returns:
            datetime: Timestamp object
        """
        return to_datetime(arg=datetime_obj,
                           unit=unit
                           )

    @staticmethod
    def datetime_strp(datetime_obj: str,
                      dtformat: str
                      ) -> datetime:
        """
        Python datetime.datetime.strptime Function Wrapper

        Parameters:
            datetime_obj (str): Datetime String to convert to datetime object.
            dtformat (str): corresponding datetime format string.

        Returns:
            datetime: datetime.datetime object
        """
        return datetime.strptime(datetime_obj,
                                 dtformat
                                 )

    @staticmethod
    def from_timestamp(datetime_obj: int) -> datetime:
        """
        Convert Epoch Time to datetime.datetime object

        Parameters:
            datetime_obj (int): Epoch datetime

        Returns:
            datetime: datetime.datetime object
        """
        return datetime.fromtimestamp(datetime_obj)

    @staticmethod
    def current_datetime() -> datetime:
        """
        Get Current System Datetime

        Returns:
            datetime: datetime.datetime object
        """
        return datetime.now()

    @staticmethod
    def time_delta(datetime_object: datetime,
                   delta: int,
                   dtformat: str,
                   default='sub'
                   ) -> str:
        """
        Add Days to a datetime.datetime object

        Parameters:
            datetime_object (datetime): datetime object
            delta (int): No. of Days to add or subtract from datetime_obj
            dtformat (str): corresponding datetime format string.
            default (str, optional): Whether to add or subtract a Day from datetime_obj ('add' | 'sub'). Defaults to 'sub'.

        Raises:
            InputError: If Wrong Value Given for default Parameter.

        Returns:
            str: A datetime string.
        """
        if default == "sub":
            return (datetime_object - timedelta(days=delta)).strftime(dtformat)
        if default == "add":
            return (datetime_object + timedelta(days=delta)).strftime(dtformat)

        raise InputError(f"Wrong default: {default}, the possible values are 'sub', 'add'")

    def pd_dateoffset(*args, **kwargs) -> DateOffset:
        """
        Datetime Increment from Pandas.

        Returns:
            DateOffset: Pandas DateOffset.
        """
        return DateOffset(*args, **kwargs)


    @staticmethod
    def concat_df(dfs: list[DataFrame]) -> DataFrame:
        return concat(dfs)


    @staticmethod
    def dates_filter(data):
        data = to_datetime(data)
        data = data[data >= datetime.now()]
        data = list(data.sort_values().date.astype(str))
        return data

    @classmethod
    def download_expiry_dates_nfo(cls, root):
        temp_session = req_session()

        for _ in range(5):
            try:
                headers = {
                    'accept': '*/*',
                    'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8,hi;q=0.7',
                    'dnt': '1',
                    'referer': 'https://www.nseindia.com/option-chain',
                    'sec-ch-ua': '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                }

                params = {
                    'symbol': f'{root}',
                }

                response = temp_session.request(method="GET", url=cls.nfo_url, params=params, cookies=cls.cookies, headers=headers, timeout=10)
                data = response.json()
                expiry_dates = data['records']['expiryDates']
                cls.expiry_dates[root] = cls.dates_filter(expiry_dates)
                return None

            except:
                pass

            try:
                response = popen(f'curl "{cls.nfo_url}?symbol={root}" -H "authority: beta.nseindia.com" -H "cache-control: max-age=0" -H "dnt: 1" -H "upgrade-insecure-requests: 1" -H "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36" -H "sec-fetch-user: ?1" -H "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9" -H "sec-fetch-site: none" -H "sec-fetch-mode: navigate" -H "accept-encoding: gzip, deflate, br" -H "accept-language: en-US,en;q=0.9,hi;q=0.8" --compressed').read()
                data = loads(response)
                expiry_dates = data['records']['expiryDates']
                cls.expiry_dates[root] = cls.dates_filter(expiry_dates)
                return None

            except:
                pass

            sleep(5)

    @classmethod
    def download_expiry_dates_bfo(cls, root):
        if root == Root.SENSEX:
            scrip_cd = 1
        elif root == Root.BANKEX:
            scrip_cd = 12

        temp_session = req_session()

        for _ in range(5):
            try:
                headers = {
                    'accept': 'application/json, text/plain, */*',
                    'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8,hi;q=0.7',
                    'dnt': '1',
                    'if-modified-since': 'Sun, 24 Mar 2024 11:21:31 GMT',
                    'origin': 'https://www.bseindia.com',
                    'referer': 'https://www.bseindia.com/',
                    'sec-ch-ua': '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-site',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                }

                params = {
                    'ProductType': 'IO',
                    'scrip_cd': scrip_cd,
                }

                response = temp_session.request(method="GET", url=cls.bfo_url, params=params, headers=headers, timeout=10)
                data = response.json()

                expiry_dates = data['Table1']
                expiry_dates = [i['ExpiryDate'] for i in expiry_dates]
                cls.expiry_dates[root] = cls.dates_filter(expiry_dates)
                return None

            except:
                pass

            try:
                response = popen(f"curl '{cls.bfo_url}?ProductType=IO&scrip_cd=1' -H 'accept: application/json, text/plain, */*' -H 'accept-language: en-GB,en-US;q=0.9,en;q=0.8,hi;q=0.7' -H 'dnt: 1' -H 'if-modified-since: Sun, 24 Mar 2024 11:21:31 GMT' -H 'origin: https://www.bseindia.com' -H 'referer: https://www.bseindia.com/' -H 'sec-ch-ua-mobile: ?0' -H 'sec-fetch-dest: empty' -H 'sec-fetch-mode: cors' -H 'sec-fetch-site: same-site' -H 'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'").read()
                data = loads(response)

                expiry_dates = data['Table1']
                expiry_dates = [i['ExpiryDate'] for i in expiry_dates]
                cls.expiry_dates[root] = cls.dates_filter(expiry_dates)
                return None

            except:
                pass

            sleep(5)

    @classmethod
    def jsonify_expiry(cls, data_frame: DataFrame) -> dict[Any, Any]:
        """
        Creates a fenix Unified Dicitonary for BankNifty & Nifty Options,
        in the following Format:

            Global[expiry][root][option][strikeprice]

            expiry: 'CURRENT' | 'NEXT' | 'FAR' | 'Expiries'(A List of All Expiries).
            root: 'BANKNIFTY' | 'NIFTY' | 'FINNIFTY | MIDCPNIFTY.
            option: 'CE' | 'PE'.
            strikeprice: Integer Values for Strike Price.

            {
                'CURRENT': {
                    'BANKNIFTY': {
                        'CE': {
                            34500: {
                                'Token': 43048,
                                'Symbol': 'BANKNIFTY2331634500CE',
                                'Expiry': '2023-03-16',
                                'Option': 'CE',
                                'StrikePrice': 34500,
                                'LotSize': 25,
                                'Root': 'BANKNIFTY',
                                'TickSize': 0.05,
                                'ExpiryName': 'CURRENT'
                                },
                    ...

                'Expiries': [
                     '2023-03-16', '2023-03-23', '2023-03-29', '2023-04-06',
                     '2023-04-13', '2023-04-27', '2023-05-25', '2023-06-29',
                     '2023-09-28', '2023-12-28', '2024-06-28', '2024-12-27',
                     '2025-06-27', '2025-12-25', '2026-06-25', '2026-12-31',
                     '2027-06-24', '2027-12-30']

            }

        Parameters:
            data_frame (DataFrame): DataFrame to Convert to fenix Unified Expiry Dictionary

        Returns:
            dict[Any, Any]: Dictioanry With 3 Most Recent Expiries for Both BankNifty & Nifty.
        """

        expiry_data = {
            WeeklyExpiry.CURRENT: {Root.BNF: {}, Root.NF: {}, Root.FNF: {}, Root.MIDCPNF: {}, Root.SENSEX: {}, Root.BANKEX: {} },
            WeeklyExpiry.NEXT: {Root.BNF: {}, Root.NF: {}, Root.FNF: {}, Root.MIDCPNF: {}, Root.SENSEX: {}, Root.BANKEX: {} },
            WeeklyExpiry.FAR: {Root.BNF: {}, Root.NF: {}, Root.FNF: {}, Root.MIDCPNF: {}, Root.SENSEX: {}, Root.BANKEX: {} },
            WeeklyExpiry.EXPIRY: {Root.BNF: [], Root.NF: [], Root.FNF: [], Root.MIDCPNF: [], Root.SENSEX: [], Root.BANKEX: []},
            WeeklyExpiry.LOTSIZE: {Root.BNF: nan, Root.NF: nan, Root.FNF: nan, Root.MIDCPNF: nan, Root.SENSEX: nan, Root.BANKEX: nan},
        }

        data_frame = data_frame.sort_values(by=['Expiry'])

        for root in [Root.BNF, Root.NF, Root.FNF, Root.MIDCPNF, Root.SENSEX, Root.BANKEX]:

            if root not in cls.expiry_dates:
                if root in [Root.SENSEX, Root.BANKEX]:
                    cls.download_expiry_dates_bfo(root=root)
                else:
                    cls.download_expiry_dates_nfo(root=root)
            small_df = data_frame[data_frame['Root'] == root]

            if small_df.shape[0]:
                expiries = small_df['Expiry'].unique()
                expiries = expiries[expiries >= str(datetime.now().date())]
                lotsize = small_df['LotSize'].unique()[0]

                dfex1 = small_df[small_df['Expiry'] == cls.expiry_dates[root][0]]
                dfex2 = small_df[small_df['Expiry'] == cls.expiry_dates[root][1]]
                dfex3 = small_df[small_df['Expiry'] == cls.expiry_dates[root][2]]

                dfexs = [("CURRENT", dfex1), ("NEXT", dfex2), ("FAR", dfex3)]

                for expiry_name, dfex in dfexs:

                    dfex['ExpiryName'] = expiry_name

                    global_dict = {'CE': {}, "PE": {}}

                    for j, i in dfex.groupby(['Option', 'StrikePrice']):
                        global_dict[j[0]][j[1]] = i.to_dict('records')[0]
                        expiry_data[expiry_name][root] = global_dict

                    expiry_data['Expiry'][root] = list(expiries)
                    expiry_data['LotSize'][root] = lotsize
            else:
                pass

        return expiry_data
