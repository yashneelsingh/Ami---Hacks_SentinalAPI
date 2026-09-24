"""Discover read-only object endpoints from an OpenAPI 3.x document."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import yaml


@dataclass(frozen=True)
class ObjectEndpoint:
    collection_path: str
    detail_path: str
    parameter_name: str


def parse_spec(source: str | dict[str, Any]) -> dict[str, Any]:
    try:
        document = source if isinstance(source, dict) else yaml.safe_load(source)
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid OpenAPI document") from exc
    if not isinstance(document, dict) or not str(document.get("openapi", "")).startswith("3."):
        raise ValueError("An OpenAPI 3.x document is required")
    if not isinstance(document.get("paths"), dict):
        raise ValueError("OpenAPI paths must be an object")
    return document


def discover_object_endpoints(document: dict[str, Any]) -> list[ObjectEndpoint]:
    paths = document["paths"]
    discovered = []
    for detail_path, path_item in paths.items():
        if not isinstance(detail_path, str) or not isinstance(path_item, dict):
            continue
        match = re.fullmatch(r"(.+)/\{([^{}]+)\}", detail_path)
        if not match:
            continue
        collection_path, parameter_name = match.groups()
        detail_get = path_item.get("get")
        collection_item = paths.get(collection_path)
        collection_get = collection_item.get("get") if isinstance(collection_item, dict) else None
        if not isinstance(detail_get, dict) or not isinstance(collection_get, dict):
            continue
        if not detail_get.get("security", document.get("security")):
            continue
        path_parameters = path_item.get("parameters", [])
        operation_parameters = detail_get.get("parameters", [])
        if not isinstance(path_parameters, list) or not isinstance(operation_parameters, list):
            continue
        parameters = path_parameters + operation_parameters
        if not any(
            isinstance(parameter, dict)
            and parameter.get("in") == "path"
            and parameter.get("name") == parameter_name
            for parameter in parameters
        ):
            continue
        discovered.append(ObjectEndpoint(collection_path, detail_path, parameter_name))
    return discovered
