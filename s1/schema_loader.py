"""Utilities for loading SentinelOne schema bundles."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def _default_schema_dir() -> Path:
    """Return the default schema directory relative to this module."""
    return Path(__file__).parent / "s1_schemas"


def _default_cache_dir() -> Path:
    """Return the default cache directory."""
    return Path(".cache")


def _normalise_dataset_name(raw: str) -> str:
    """Normalise dataset names to a predictable identifier."""

    cleaned = raw.strip().lower()
    return cleaned.replace(" ", "_")


_SYNTHETIC_COMMON_FIELDS: Dict[str, Dict[str, str]] = {
    "meta.event.name": {
        "description": "Event name (PROCESSCREATION, FILECREATION, etc.) used for dataset filters",
        "data_type": "String",
    },
}


def _apply_synthetic_fields(schema: Dict[str, Any]) -> None:
    """Ensure synthetic common fields exist in the aggregated schema."""

    if not isinstance(schema, dict):
        return

    common_fields = schema.setdefault("common_fields", {})
    if not isinstance(common_fields, dict):
        common_fields = {}
        schema["common_fields"] = common_fields

    for field_name, field_meta in _SYNTHETIC_COMMON_FIELDS.items():
        common_fields.setdefault(field_name, field_meta)


def _parse_fields(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    fields: Dict[str, Dict[str, Any]] = {}
    for entry in payload.get("fields", []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("s1ql_field")
        if not isinstance(name, str) or not name:
            continue
        fields[name] = {
            "description": entry.get("description", ""),
            "data_type": entry.get("data_type", "Unknown"),
        }
    return fields


@dataclass
class S1SchemaCache:
    """Aggregate the SentinelOne schema JSON files into a single structure."""

    schema_dir: Path = field(default_factory=_default_schema_dir)
    cache_dir: Path = field(default_factory=_default_cache_dir)
    _cache: Optional[Dict[str, Any]] = field(default=None, init=False)
    _cache_version: int = field(default=0, init=False)
    _source_signature: Optional[str] = field(default=None, init=False)

    def __post_init__(self):
        """Initialize cache file path."""
        self.cache_file = self.cache_dir / "s1_schema_cache.json"
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)

    def load(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Load the aggregated schema, refreshing when files change."""

        directory = Path(self.schema_dir)
        if not directory.exists():
            raise FileNotFoundError(f"Schema directory does not exist: {directory}")

        signature = self._compute_signature()
        
        # Try to load from disk cache first
        if not force_refresh and signature and self._cache is None:
            cached = self._load_from_disk(signature)
            if cached is not None:
                self._cache = cached["schema"]
                _apply_synthetic_fields(self._cache)
                self._cache_version = cached.get("version", 0)
                self._source_signature = signature
                datasets = self._cache.get("datasets", {})
                common_fields = self._cache.get("common_fields", {})
                logger.info(
                    "S1 schema cache warmed from disk (%d datasets, %d common fields)",
                    len(datasets),
                    len(common_fields),
                )
                return self._cache
        
        # Return existing cache if signature matches
        if not force_refresh and self._cache is not None and signature == self._source_signature:
            _apply_synthetic_fields(self._cache)
            return self._cache

        # Load from source files
        aggregated: Dict[str, Any] = {
            "datasets": {},
            "common_fields": {},
            "operators": {},
            "operator_variants": {},
            "shortcuts": [],
            "regex_reference": {},
        }

        for path in sorted(directory.glob("s1_*.json")):
            try:
                with path.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Failed to parse %s: %s", path.name, exc)
                continue

            name = path.name
            if name == "s1_common_data_fields.json":
                aggregated["common_fields"] = _parse_fields(payload)
                continue

            if name.startswith("s1_operators"):
                key = name.replace("s1_", "").replace(".json", "")
                aggregated["operator_variants"][key] = payload.get("operators", [])
                if name == "s1_operators.json":
                    aggregated["operators"] = payload
                continue

            if name == "s1_shortcut_queries.json":
                shortcuts = payload.get("shortcuts", [])
                if isinstance(shortcuts, list):
                    aggregated["shortcuts"] = shortcuts
                continue

            if name == "s1_regex_reference.json":
                aggregated["regex_reference"] = payload
                continue

            fields = _parse_fields(payload)
            metadata = payload.get("metadata", {})
            schema_name = metadata.get("schema_name") or name
            if not isinstance(schema_name, str):
                schema_name = name
            dataset_key = _normalise_dataset_name(schema_name)
            aggregated["datasets"][dataset_key] = {
                "name": schema_name,
                "metadata": metadata,
                "fields": fields,
            }

        # Inject synthetic common fields that are required for validation but not present in source bundles
        _apply_synthetic_fields(aggregated)

        self._cache = aggregated
        self._cache_version += 1
        self._source_signature = signature
        
        # Persist to disk
        self._persist_to_disk()
        
        logger.info(
            "Loaded SentinelOne schema bundle with %d datasets and %d common fields",
            len(aggregated["datasets"]),
            len(aggregated["common_fields"]),
        )
        return aggregated
    
    def _compute_signature(self) -> Optional[str]:
        """Compute a signature based on all source files' modification times and sizes."""
        directory = Path(self.schema_dir)
        if not directory.exists():
            return None
        
        hasher = hashlib.blake2s(digest_size=16)
        found = False
        
        for path in sorted(directory.glob("s1_*.json")):
            try:
                stats = path.stat()
                hasher.update(path.name.encode("utf-8"))
                hasher.update(str(stats.st_mtime_ns).encode("utf-8"))
                hasher.update(str(stats.st_size).encode("utf-8"))
                found = True
            except OSError:
                continue
        
        return hasher.hexdigest() if found else None
    
    def _load_from_disk(self, expected_signature: str) -> Optional[Dict[str, Any]]:
        """Load cached schema from disk if signature matches."""
        if not self.cache_file.exists():
            return None
        
        try:
            with self.cache_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            
            if data.get("signature") != expected_signature:
                logger.debug("S1 cache signature mismatch, will reload from source")
                return None
            
            if not isinstance(data.get("schema"), dict):
                return None
            
            return data
        except Exception as exc:
            logger.warning("Failed to load S1 cache from disk: %s", exc)
            return None
    
    def _persist_to_disk(self) -> None:
        """Save the current schema cache to disk."""
        try:
            data = {
                "schema": self._cache,
                "signature": self._source_signature,
                "version": self._cache_version,
            }
            with self.cache_file.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.warning("Failed to persist S1 cache to disk: %s", exc)

    def datasets(self) -> Dict[str, Any]:
        schema = self.load()
        datasets = schema.get("datasets", {})
        return datasets if isinstance(datasets, dict) else {}

    def list_fields(self, dataset: str) -> Dict[str, Dict[str, Any]]:
        datasets = self.datasets()
        meta = datasets.get(dataset, {})
        fields = meta.get("fields", {})
        return fields if isinstance(fields, dict) else {}

    def common_fields(self) -> Dict[str, Dict[str, Any]]:
        schema = self.load()
        common = schema.get("common_fields", {})
        return common if isinstance(common, dict) else {}
