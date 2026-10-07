"""thresholds.yml loading with mtime-based hot reload.

Daemons call load() once per loop iteration; the file is only re-parsed when
it changed on disk, so policy edits take effect without a restart. A deleted
or malformed file keeps the last good policy rather than killing the daemon.
"""

import os

import yaml

_cache: tuple[tuple[str, float], dict] | None = None


def load() -> dict:
    global _cache
    path = os.getenv("THRESHOLDS", "config/thresholds.yml")
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        if _cache is not None:
            return _cache[1]
        raise
    if _cache is None or _cache[0] != (path, mtime):
        try:
            with open(path) as f:
                new = yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as e:
            if _cache is not None:
                print(f"[policy] reload failed ({e}); keeping previous thresholds")
                return _cache[1]
            raise
        if _cache is not None:
            print(f"[policy] thresholds reloaded from {path}")
        _cache = ((path, mtime), new)
    return _cache[1]
