from __future__ import annotations

from typing import Any

from fenix.symphony import Symphony


class MotilalOswal(Symphony):
    """
    Motilal Oswal fenix Broker Class

    Returns:
        fenix.motilaloswal: fenix Motilal Oswal Broker Object
    """

    id = "MotilalOswal"

    # Motilal Oswal hosts the Symphony/XTS API under its own domain. The
    # endpoint paths match Symphony exactly, so ``_API['paths']`` is inherited
    # and only the server hosts are overridden here. ``get_url`` builds every
    # request URL from ``servers[...] + paths[...]['path']``, and the base
    # class deep-copies ``servers`` per instance, so the dynamic-base rewrite
    # in ``Symphony.authenticate`` stays isolated.
    _API = {
        **Symphony._API,
        "servers": {
            "interactive": "https://moxtsapi.motilaloswal.com:3000/interactive",
            "hostlookup": "https://moxtsapi.motilaloswal.com:3000",
            "market_data": "https://moxtsapi.motilaloswal.com:3000/apimarketdata",
            "market_data_binary": (
                "https://moxtsapi.motilaloswal.com:3000/apibinarymarketdata"
            ),
        },
    }

    def describe(self) -> dict[str, Any]:
        """Return broker metadata, re-branding the inherited Symphony id."""
        description = super().describe()
        description["id"] = self.id
        return description
