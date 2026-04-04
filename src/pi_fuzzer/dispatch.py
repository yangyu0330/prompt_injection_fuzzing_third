from __future__ import annotations

import os
from copy import deepcopy
from typing import Any

import httpx

from .models import TargetConfig


def _render_obj(obj: Any, variables: dict[str, Any]) -> Any:
    if isinstance(obj, dict):
        return {k: _render_obj(v, variables) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_render_obj(v, variables) for v in obj]
    if isinstance(obj, str):
        try:
            return obj.format(**variables)
        except KeyError:
            return obj
    return obj


def _dot_get(obj: Any, path: str) -> Any:
    cur = obj
    for token in path.split("."):
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(token)
        else:
            return None
    return cur


def build_request_payload(target: TargetConfig, variables: dict[str, Any]) -> dict[str, Any]:
    template = deepcopy(target.body_template)
    return _render_obj(template, variables)


def map_response(response_data: dict[str, Any], response_field_map: dict[str, str]) -> dict[str, Any]:
    mapped: dict[str, Any] = {}
    for out_key, path in response_field_map.items():
        mapped[out_key] = _dot_get(response_data, path)
    return mapped


def dispatch_http(target: TargetConfig, payload: dict[str, Any]) -> dict[str, Any]:
    headers = dict(target.headers)
    auth_cfg = target.auth or {}
    if auth_cfg.get("type") == "bearer_env":
        env_var = auth_cfg.get("env_var")
        token = os.getenv(env_var, "") if env_var else ""
        if token:
            headers["Authorization"] = f"Bearer {token}"

    method = (target.method or "POST").upper()
    timeout = float(target.timeout_sec)
    with httpx.Client(timeout=timeout) as client:
        resp = client.request(method, target.url or "", headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
    return data

