from fenix.symphony import symphony


class motilaloswal(symphony):
    """
    Motilal Oswal fenix Broker Class

    Returns:
        fenix.motilaloswal: fenix Motilal Oswal Broker Object
    """

    # Market Data Dictonaries

    id = "motilaloswal"

    # Base URLs

    base_urls = {
        "api_doc": "https://moxtsapi.motilaloswal.com:3000/doc/interactive",
        "marketdata_doc": "https://moxtsapi.motilaloswal.com:3000/apimarketdata/instruments/master",
        "base": "https://moxtsapi.motilaloswal.com:3000/interactive",
        "access_token": "https://moxtsapi.motilaloswal.com:3000/interactive/user/session",
        "market_data": "https://moxtsapi.motilaloswal.com:3000/apimarketdata/instruments/master",
        "index_data": "https://moxtsapi.motilaloswal.com:3000/apimarketdata//instruments/indexlist",
    }

    urls = {
        "place_order": f"{base_urls['base']}/orders",
        "modify_order": f"{base_urls['base']}/orders",
        "cancel_order": f"{base_urls['base']}/orders",
        "order_history": f"{base_urls['base']}/orders",
        "orderbook": f"{base_urls['base']}/orders",
        "tradebook": f"{base_urls['base']}/orders/trades",
        "positions": f"{base_urls['base']}/portfolio/positions",
        "holdings": f"{base_urls['base']}/portfolio/holdings",
        "profile": f"{base_urls['base']}/user/profile",
        "rms_limits": f"{base_urls['base']}/user/balance",
    }