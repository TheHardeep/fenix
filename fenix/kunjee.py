from fenix.symphony import symphony


class kunjee(symphony):
    """
    Kunjee fenix Broker Class

    Returns:
        fenix.kunjee: fenix Kunjee Broker Object
    """

    # Market Data Dictonaries

    id = "kunjee"

    # Base URLs

    base_urls = {
        "api_doc": "https://trade.kunjee.net:3000/doc/interactive",
        "marketdata_doc": "https://trade.kunjee.net:3000/apimarketdata/instruments/master",
        "base": "https://trade.kunjee.net:3000/interactive",
        "access_token": "https://trade.kunjee.net:3000/interactive/user/session",
        "market_data": "https://trade.kunjee.net:3000/apimarketdata/instruments/master",
        "index_data": "https://trade.kunjee.net:3000/apimarketdata//instruments/indexlist",
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