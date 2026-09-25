"""Context injection for System-1: asset inventory + recent escalation counts."""

import json
import os

import yaml

from . import store

ASSETS_PATH = os.getenv("ASSETS", "config/assets.yml")


def load_assets() -> dict:
    with open(ASSETS_PATH) as f:
        return yaml.safe_load(f)


def build_state(event: dict, window_sec: int, assets: dict | None = None) -> str:
    assets = assets or load_assets()
    host, user = event.get("host"), event.get("user")
    hinfo = (assets.get("hosts") or {}).get(host, {})
    uinfo = (assets.get("users") or {}).get(user, {})
    host_hits = store.escalation_count(host, None, window_sec) if host else 0
    user_hits = store.escalation_count(None, user, window_sec) if user else 0
    return (
        f"LOG EVENT\n"
        f"source={event.get('source')} host={host} user={user} ts={event.get('ts_iso')}\n"
        f"{json.dumps(event.get('raw'), indent=2)}\n\n"
        f"ENRICHMENT\n"
        f"- host criticality: {hinfo.get('criticality', 'unknown')}/5 "
        f"({hinfo.get('type', hinfo.get('role', 'unknown'))}, owner={hinfo.get('owner', 'n/a')})\n"
        f"- user: role={uinfo.get('role', 'unknown')}, admin={uinfo.get('admin', 'unknown')}\n"
        f"- escalated events involving this host in last {window_sec // 60}m: {host_hits}\n"
        f"- escalated events involving this user in last {window_sec // 60}m: {user_hits}\n"
    )
