"""Complete, bounded pagination of the native Anthropic Models API."""

from collections.abc import Mapping

MAX_CATALOG_PAGES = 20
PAGE_SIZE = 1000


def fetch_anthropic_catalog(proxy_service_cls, *, url, headers, max_models):
    """Return a complete snapshot; incomplete pages never replace a good catalog."""
    rows = []
    cursors = set()
    params = {"limit": PAGE_SIZE}
    for _ in range(MAX_CATALOG_PAGES):
        response = proxy_service_cls.make_request(
            method="GET",
            url=url,
            headers=headers,
            params=params.copy(),
            data=None,
            api_provider="anthropic",
            use_cache=False,
            timeout_override=(3, 10),
            force_raw_passthrough=True,
        )
        try:
            status = int(response.status_code)
            if not 200 <= status < 300:
                return status, None
            payload = response.json()
        finally:
            response.close()
        if not isinstance(payload, Mapping) or not isinstance(
            payload.get("data"), list
        ):
            raise ValueError("Invalid Anthropic catalog page")
        more = payload.get("has_more", False)
        if not isinstance(more, bool):
            raise ValueError("Invalid Anthropic catalog pagination")
        rows.extend(payload["data"])
        if len(rows) > max_models:
            raise ValueError("Anthropic catalog exceeds refresh limit")
        if not more:
            return status, {"data": rows}
        cursor = payload.get("last_id")
        page_ids = {
            item.get("id")
            for item in payload["data"]
            if isinstance(item, Mapping) and isinstance(item.get("id"), str)
        }
        if (
            not isinstance(cursor, str)
            or not cursor
            or cursor in cursors
            or cursor not in page_ids
        ):
            raise ValueError("Invalid Anthropic catalog cursor")
        cursors.add(cursor)
        params["after_id"] = cursor
    raise ValueError("Anthropic catalog exceeds page limit")
