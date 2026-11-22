"""Deprecated alias for :mod:`attackmap.foundation.secrets` (AR030).

LLM credential storage is OS-keychain infrastructure, not a presentation
surface: the orchestration worker/provider need it, and the layer map
forbids upward imports into ``surfaces``. The module moved to foundation
in AR030; this shim re-exports the historical surface for one release so
existing ``from attackmap.surfaces.ui.secrets import ...`` call sites keep
working. Import from ``attackmap.foundation.secrets`` instead; this
module is removed after that release.
"""
from __future__ import annotations

from attackmap.foundation.secrets import (  # noqa: F401
    child_llm_env,
    has_llm_key,
    is_loopback_endpoint,
    load_llm_key,
    save_llm_key,
)
from attackmap.foundation.secrets import (  # noqa: F401  (test-visible internals)
    _data_dir,
    _key_path,
    _protect,
    _unprotect,
)

__all__ = [
    "child_llm_env",
    "has_llm_key",
    "is_loopback_endpoint",
    "load_llm_key",
    "save_llm_key",
]
