from __future__ import annotations
from datetime import datetime
from datetime import timedelta
from json import dumps
from json import loads
from ssl import SSLError
from typing import Any
from pandas import DataFrame
from pandas import read_csv
from pandas import read_json
from pandas import to_datetime
from pandas import options
from pyotp import TOTP


from requests.sessions import session as req_session
from requests.models import Response
from requests.exceptions import HTTPError
from requests.exceptions import Timeout
from requests.exceptions import TooManyRedirects
from requests.exceptions import RequestException
from requests.exceptions import ConnectionError as requestsConnectionError

from kronos.base.constants import Root
from kronos.base.constants import WeeklyExpiry

from kronos.base.errors import InputError
from kronos.base.errors import ResponseError
from kronos.base.errors import RequestTimeout
from kronos.base.errors import NetworkError
from kronos.base.errors import BrokerError

options.mode.chained_assignment = None


__all__ = [
    'Exchange',
]


class Exchange:

    """ Base Class Common to All Brokers """

    id = ''
    _session = None

    def __repr__(self):
        return f"kronos.{self.id}()"

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
            print(response)
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
        return loads(response.text.strip())


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


    @staticmethod
    def jsonify_expiry(data_frame: DataFrame) -> dict[Any, Any]:
        """
        Creates a kronos Unified Dicitonary for BankNifty & Nifty Options,
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
            data_frame (DataFrame): DataFrame to Convert to kronos Unified Expiry Dictionary

        Returns:
            dict[Any, Any]: Dictioanry With 3 Most Recent Expiries for Both BankNifty & Nifty.
        """

        expiry_data = {
            WeeklyExpiry.CURRENT: {Root.BNF: {}, Root.NF: {}, Root.FNF: {}, Root.MIDCPNF: {}},
            WeeklyExpiry.NEXT: {Root.BNF: {}, Root.NF: {}, Root.FNF: {}, Root.MIDCPNF: {}},
            WeeklyExpiry.FAR: {Root.BNF: {}, Root.NF: {}, Root.FNF: {}, Root.MIDCPNF: {}},
            WeeklyExpiry.EXPIRY: {Root.BNF: [], Root.NF: [], Root.FNF: [], Root.MIDCPNF: []},
            WeeklyExpiry.LOTSIZE: {Root.BNF: [], Root.NF: [], Root.FNF: [], Root.MIDCPNF: []},
        }

        data_frame = data_frame.sort_values(by=['Expiry'])

        for root in [Root.BNF, Root.NF, Root.FNF, Root.MIDCPNF]:


            expiries = data_frame[data_frame['Root'] == root]['Expiry'].unique()
            expiries = expiries[expiries >= str(datetime.now().date())]
            lotsize = data_frame[data_frame['Root'] == root]['LotSize'].unique()[0]

            dfex1 = data_frame[data_frame['Expiry'] == expiries[0]]
            dfex2 = data_frame[data_frame['Expiry'] == expiries[1]]
            dfex3 = data_frame[data_frame['Expiry'] == expiries[2]]

            dfexs = [("CURRENT", dfex1), ("NEXT", dfex2), ("FAR", dfex3)]

            for expiry_name, dfex in dfexs:

                dfex['ExpiryName'] = expiry_name

                global_dict = {'CE': {}, "PE": {}}

                for j, i in dfex.groupby(['Option', 'StrikePrice']):
                    global_dict[j[0]][j[1]] = i.to_dict('records')[0]
                    expiry_data[expiry_name][root] = global_dict

                expiry_data['Expiry'][root] = expiries
                expiry_data['LotSize'][root] = lotsize

        return expiry_data
