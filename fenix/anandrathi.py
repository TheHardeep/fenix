from __future__ import annotations

from typing import Any

from fenix.symphony import Symphony

from fenix.base.errors import TokenDownloadError


class AnandRathi(Symphony):
    """Anand Rathi broker adapter for the Fenix trading interface.

    Anand Rathi exposes a Symphony-compatible Interactive API hosted on
    ``algozy.rathi.com``. Only two things differ from the upstream Symphony
    deployment:

    * The Interactive base URL is dynamic — the client must call ``HostLookup``
      at the start of every session to discover the actual ``connectionString``
      plus a session ``uniqueKey``. Anand Rathi additionally publishes static
      fallback endpoints used when the primary lookup is unreachable.
    * The API is reached at broker-specific hosts.

    Everything else — the auth-token exchange, contract-master parsing, the
    order/portfolio/profile endpoints, the error envelope, and the rate-limit
    buckets — is inherited unchanged from :class:`Symphony`.
    """

    # Anand Rathi runs the Symphony/XTS API under its own domain. The endpoint
    # paths are identical to Symphony, so ``_API['paths']`` is inherited and
    # only the server hosts (and doc links) are overridden. ``get_url`` builds
    # every request URL from ``servers[...] + paths[...]['path']``, and the
    # base class deep-copies ``servers`` per instance so the dynamic-base
    # rewrite in ``authenticate`` stays isolated.
    _API = {
        **Symphony._API,
        "doc": "https://algozy.rathi.com/doc/interactive",
        "marketdata_doc": "https://algozy.rathi.com/doc/marketdata/",
        "servers": {
            # The Interactive base URL is dynamic — ``authenticate`` resolves
            # it through HostLookup and overwrites this entry. The default
            # ``HOSTLOOKUP`` alias keeps ``get_url`` working before
            # authentication for callers that only need market-data endpoints.
            "interactive": "https://algozy.rathi.com/HOSTLOOKUP",
            "market_data": "https://algozy.rathi.com/apimarketdata",
            "hostlookup": "https://algozy.rathi.com",
        },
    }

    # Documented HostLookup fallbacks — used (in order) when the primary
    # ``/hostlookup`` endpoint is unreachable. Each entry is
    # ``(connection_string, unique_key)``.
    _HOSTLOOKUP_FALLBACKS = (
        (
            "https://algozy.rathi.com/1hostlookup",
            "K0j+aTs2AmSzf68MvHSL16twVovAXMWxfOEUk5sG2GFQKJJCNBKkCE9Wgmq9LbK0",
        ),
        (
            "https://algozy.rathi.com/2hostlookup",
            "vfOMWTmnZgdmiskhZooUqEWqyxjQKnog5YzT4eu8FroSuRbqhxHMbzMipNl2Ouus",
        ),
        (
            "https://algozy.rathi.com/3hostlookup",
            "DqnqUXrFQFzQKXS+BpFSxDJwN7Yazrolquy3PXD/KqmpecyR/xG6s3Up+ef/c0hP",
        ),
        (
            "https://algozy.rathi.com/4hostlookup",
            "MKT7Ck0EhRzjk+Y5cG1AT8HELOrg409DKdhftbGfoKw2zcz6g49auYYzVOF5aYAh",
        ),
    )

    def describe(self) -> dict[str, Any]:
        """Return broker metadata, re-branding the inherited Symphony id.

        ``tokenParams``, ``sensitiveLogKeys``, and the rate-limit buckets are
        identical to the Symphony deployment, so they are inherited unchanged.
        """
        description = super().describe()
        description["id"] = "AnandRathi"
        return description

    # --- Authentication -----------------------------------------------------

    def _resolve_interactive_base(self) -> tuple[str | None, str | None]:
        """Resolve the dynamic Interactive base URL via HostLookup.

        Delegates the HostLookup round-trip to
        :meth:`Symphony._resolve_interactive_base` and, when that lookup is
        unavailable, falls back to the first documented endpoint in
        ``_HOSTLOOKUP_FALLBACKS``.

        Returns:
            ``(connection_string, unique_key)`` from HostLookup, or the first
            documented fallback pair when the lookup fails.
        """
        connection_string, unique_key = super()._resolve_interactive_base()
        if connection_string and unique_key:
            return connection_string, unique_key
        return self._HOSTLOOKUP_FALLBACKS[0]

    # --- Contract-Master Bulk Download -------------------------------------

    def download_tokens(self) -> tuple[dict, dict, dict, dict]:
        """Download every contract-master segment in a single request.

        Anand Rathi returns one pipe-delimited blob covering every requested
        segment, so a single network call can feed all of the inherited
        ``load_*_tokens`` parsers — each one filters the shared blob down to
        the exchanges it owns.

        Returns:
            ``(equity, options, futures, all_tokens)`` dictionaries built from
            the consolidated contract-master payload.
        """
        try:
            response = self.fetch(
                method="POST",
                url=self.get_url("instruments"),
                endpoint_group="default",
                json={
                    "exchangeSegmentList": [
                        "NSECM",
                        "BSECM",
                        "NSEFO",
                        "BSEFO",
                        "MCXFO",
                        "NSECD",
                    ],
                },
            )
            raw_string = self._parse_json_response(response)["result"]
        except Exception as exc:  # noqa: BLE001
            raise TokenDownloadError({"Error": exc.args}) from exc

        eq_data, eq_tok = self.load_equity_tokens(
            {"NSE": raw_string, "BSE": raw_string},
        )
        fno_data, fno_tok = self.load_fno_tokens(
            {"NFO": raw_string, "BFO": raw_string},
        )
        mcx_data, mcx_tok = self.load_mcx_tokens({"MCX": raw_string})
        cds_data, cds_tok = self.load_cds_tokens(
            {"CDS": raw_string, "BCD": raw_string},
        )

        options = {
            **fno_data["Options"],
            **mcx_data["Options"],
            **cds_data["Options"],
        }
        futures = {
            **fno_data["Futures"],
            **mcx_data["Futures"],
            **cds_data["Futures"],
        }

        all_tokens: dict[str, Any] = {}
        all_tokens.update(eq_tok)
        all_tokens.update(fno_tok)
        all_tokens.update(mcx_tok)
        all_tokens.update(cds_tok)

        return (
            eq_data["Equity"],
            options,
            futures,
            all_tokens,
        )
