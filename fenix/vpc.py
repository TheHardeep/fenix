from fenix.symphony import symphony


class vpc(symphony):
    """
    VPC fenix Broker Class

    Returns:
        fenix.vpc: fenix VPC Broker Object
    """

    # Market Data Dictonaries

    id = "vpc"

    # Base URLs

    base_urls = {
        "api_doc": "http://122.160.19.15:3000/doc/interactive",
        "marketdata_doc": "http://122.160.19.15:3000/apimarketdata/instruments/master",
        "base": "http://122.160.19.15:3000/interactive",
        "access_token": "http://122.160.19.15:3000/interactive/user/session",
        "market_data": "http://122.160.19.15:3000/apimarketdata/instruments/master",
        "index_data": "http://122.160.19.15:3000/apimarketdata//instruments/indexlist",
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
