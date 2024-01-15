from kronos.symphony import symphony


class kunjee(symphony):
    """
    Kunjee kronos Broker Class

    Returns:
        kronos.kunjee: kronos Kunjee Broker Object
    """


    # Market Data Dictonaries

    id = 'kunjee'


    # Base URLs

    base_urls = {
        "api_documentation_url": "https://trade.kunjee.net:3000/doc/interactive",
        "market_data_url": "https://trade.kunjee.net:3000/apimarketdata/instruments/master",
        "base_url": "https://trade.kunjee.net:3000/interactive",
        "access_token": "https://trade.kunjee.net:3000/interactive/user/session"
    }
