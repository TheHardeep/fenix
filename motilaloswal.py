from fenix.symphony import symphony


class motilaloswal(symphony):
    """
    Motilal Oswal fenix Broker Class

    Returns:
        fenix.motilaloswal: fenix Motilal Oswal Broker Object
    """


    # Market Data Dictonaries

    id = 'motilaloswal'


    # Base URLs

    base_urls = {
        "api_documentation_url": "https://moxtsapi.motilaloswal.com:3000/doc/interactive",
        "market_data_url": "https://moxtsapi.motilaloswal.com:3000/apimarketdata/instruments/master",
        "base_url": "https://moxtsapi.motilaloswal.com:3000/interactive",
        "access_token": "https://moxtsapi.motilaloswal.com:3000/interactive/user/session"
    }
