from fenix.symphony import symphony


class kunjee(symphony):
    """
    Kunjee fenix Broker Class

    Returns:
        fenix.kunjee: fenix Kunjee Broker Object
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
