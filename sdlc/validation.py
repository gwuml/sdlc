"""Validation helpers for run artifacts and command payloads."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def validate_json_schema(data: Any, schema: Mapping[str, Any]) -> list[str]:
    """Validate data against a JSON Schema.

    The project does not require a JSON Schema dependency. When jsonschema is
    installed, use it. Otherwise, fall back to the schema subset used by the
    checked-in SDLC schemas.
    """
    try:
        from jsonschema import Draft202012Validator  # type: ignore[import-not-found]
    except ImportError:
        return _validate_schema_subset(data, schema)

    validator = Draft202012Validator(schema)
    return [
        f"{'/'.join(str(part) for part in error.path) or '$'}: {error.message}"
        for error in sorted(validator.iter_errors(data), key=lambda item: list(item.path))
    ]


def _validate_schema_subset(data: Any, schema: Mapping[str, Any], path: str = "$") -> list[str]:
    errors: list[str] = []
    allowed = schema.get("enum")
    if allowed is not None and data not in allowed:
        errors.append(f"{path}: expected one of {allowed}, got {data!r}")

    expected_type = schema.get("type")
    if expected_type is not None and not _matches_json_type(data, expected_type):
        errors.append(f"{path}: expected type {expected_type}, got {_json_type_name(data)}")
        return errors

    if schema.get("type") == "object" or isinstance(data, dict):
        if not isinstance(data, dict):
            return errors
        required = schema.get("required", [])
        for key in required:
            if key not in data:
                errors.append(f"{path}.{key}: missing required property")
        properties = schema.get("properties", {})
        if isinstance(properties, Mapping):
            for key, child_schema in properties.items():
                if key in data and isinstance(child_schema, Mapping):
                    errors.extend(_validate_schema_subset(data[key], child_schema, f"{path}.{key}"))
            if schema.get("additionalProperties") is False:
                for key in data:
                    if key not in properties:
                        errors.append(f"{path}.{key}: additional property is not allowed")

    if schema.get("type") == "array" or isinstance(data, list):
        if not isinstance(data, list):
            return errors
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(data):
                errors.extend(_validate_schema_subset(item, item_schema, f"{path}[{index}]"))

    return errors


def _matches_json_type(data: Any, expected_type: Any) -> bool:
    if isinstance(expected_type, list):
        return any(_matches_json_type(data, item) for item in expected_type)
    if expected_type == "object":
        return isinstance(data, dict)
    if expected_type == "array":
        return isinstance(data, list)
    if expected_type == "string":
        return isinstance(data, str)
    if expected_type == "boolean":
        return isinstance(data, bool)
    if expected_type == "integer":
        return type(data) is int
    if expected_type == "number":
        return type(data) in {int, float}
    if expected_type == "null":
        return data is None
    return True


def _json_type_name(data: Any) -> str:
    if data is None:
        return "null"
    if isinstance(data, bool):
        return "boolean"
    if isinstance(data, dict):
        return "object"
    if isinstance(data, list):
        return "array"
    if isinstance(data, str):
        return "string"
    if isinstance(data, int):
        return "integer"
    if isinstance(data, float):
        return "number"
    return type(data).__name__
