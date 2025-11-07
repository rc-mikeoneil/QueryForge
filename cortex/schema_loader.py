from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CortexSchemaCache:
    """Load and cache the Cortex XDR XQL schema file."""

    DATASET_FIELD_MAP = {
        "xdr_data": "xdr_data_fields",
    }

    def __init__(self, schema_path: Path, cache_dir: Optional[Path] = None) -> None:
        self.schema_path = Path(schema_path)
        self._lock = threading.Lock()
        self._cache: Dict[str, Any] | None = None
        self._cache_version: int = 0
        self._source_signature: Optional[str] = None
        
        if cache_dir is None:
            cache_dir = Path(".cache")
        self.cache_file = cache_dir / "cortex_schema_cache.json"
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)

    def load(self, force_refresh: bool = False) -> Dict[str, Any]:
        with self._lock:
            if force_refresh or self._cache is None:
                signature = self._compute_signature()
                
                # Try to load from disk cache first
                if not force_refresh and signature:
                    cached = self._load_from_disk(signature)
                    if cached is not None:
                        self._cache = cached["schema"]
                        self._cache_version = cached.get("version", 0)
                        self._source_signature = signature
                        datasets = self._cache.get("datasets", {})
                        logger.info("Cortex schema cache warmed from disk (%d datasets)", len(datasets))
                        return self._cache
                
                # Load from source - try multi-file pattern first, fall back to monolithic
                payload = self._load_split_schema()
                if payload is None:
                    payload = self._load_monolithic_schema()
                
                self._cache = payload
                self._cache_version += 1
                self._source_signature = signature
                
                # Persist to disk
                self._persist_to_disk()
                
                datasets = payload.get("datasets", {})
                logger.info("Loaded Cortex schema with %d datasets", len(datasets))
            return self._cache
    
    def _compute_signature(self) -> Optional[str]:
        """Compute a signature based on the source file's modification time and size."""
        try:
            stats = self.schema_path.stat()
            hasher = hashlib.blake2s(digest_size=16)
            hasher.update(self.schema_path.name.encode("utf-8"))
            hasher.update(str(stats.st_mtime_ns).encode("utf-8"))
            hasher.update(str(stats.st_size).encode("utf-8"))
            return hasher.hexdigest()
        except OSError:
            return None
    
    def _load_from_disk(self, expected_signature: str) -> Optional[Dict[str, Any]]:
        """Load cached schema from disk if signature matches."""
        if not self.cache_file.exists():
            return None
        
        try:
            with self.cache_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            
            if data.get("signature") != expected_signature:
                logger.debug("Cortex cache signature mismatch, will reload from source")
                return None
            
            if not isinstance(data.get("schema"), dict):
                return None
            
            return data
        except Exception as exc:
            logger.warning("Failed to load Cortex cache from disk: %s", exc)
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
            logger.warning("Failed to persist Cortex cache to disk: %s", exc)
    
    def _load_split_schema(self) -> Optional[Dict[str, Any]]:
        """Load schema from multiple cortex_*.json files and merge them."""
        schema_dir = self.schema_path.parent
        cortex_files = sorted(schema_dir.glob("cortex_*.json"))

        if not cortex_files:
            return None

        logger.info("Loading Cortex schema from %d split files", len(cortex_files))
        merged: Dict[str, Any] = {}

        for file_path in cortex_files:
            try:
                with file_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)

                if not isinstance(data, dict):
                    continue

                payload = data.get("cortex_xdr_query_schema")
                if not isinstance(payload, dict):
                    continue

                # Deep merge the payload into merged
                for key, value in payload.items():
                    if key not in merged:
                        merged[key] = value
                    elif isinstance(merged[key], dict) and isinstance(value, dict):
                        merged[key].update(value)
                    else:
                        merged[key] = value

            except Exception as exc:
                logger.warning("Failed to load %s: %s", file_path.name, exc)
                continue

        if not merged:
            return None

        # Load and merge field definition files
        self._load_and_merge_field_files(schema_dir, merged)

        logger.info("Merged Cortex schema from split files")
        return merged

    def _load_and_merge_field_files(self, schema_dir: Path, merged: Dict[str, Any]) -> None:
        """Load field definition files and merge them into xdr_data_fields."""
        # Find all JSON files that might contain field definitions
        field_files = [
            f for f in sorted(schema_dir.glob("*.json"))
            if not f.name.startswith("cortex_")
        ]

        if not field_files:
            return

        xdr_fields: Dict[str, Dict[str, Any]] = {}

        for file_path in field_files:
            try:
                with file_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)

                if not isinstance(data, dict):
                    continue

                # Check for fields array in various formats
                fields = data.get("fields", [])
                if not isinstance(fields, list) or not fields:
                    continue

                # Convert fields to the expected format
                for field in fields:
                    if not isinstance(field, dict):
                        continue

                    # Handle both 'field_name' and 'name' as the field identifier
                    field_name = field.get("field_name") or field.get("name")
                    if not field_name:
                        continue

                    # Build field metadata
                    field_meta: Dict[str, Any] = {}

                    # Map data_type to type
                    data_type = field.get("data_type")
                    if data_type:
                        field_meta["type"] = data_type

                    # Add description
                    description = field.get("description")
                    if description:
                        field_meta["description"] = description

                    # Add mode/nullability
                    mode = field.get("mode")
                    if mode:
                        field_meta["mode"] = mode

                    # Add any other metadata
                    for key in field:
                        if key not in ("field_name", "name", "data_type", "description", "mode"):
                            field_meta[key] = field[key]

                    # Store the field (don't overwrite if already exists)
                    if field_name not in xdr_fields:
                        xdr_fields[field_name] = field_meta

            except Exception as exc:
                logger.warning("Failed to load field file %s: %s", file_path.name, exc)
                continue

        # Merge the collected fields into the schema
        if xdr_fields:
            merged["xdr_data_fields"] = xdr_fields
            logger.info("Loaded %d field definitions from field files", len(xdr_fields))
    
    def _load_monolithic_schema(self) -> Dict[str, Any]:
        """Load schema from single cortex_xdr_schema.json file."""
        logger.info("Loading Cortex XDR schema from %s", self.schema_path.name)
        raw = self.schema_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Schema root must be a JSON object")
        payload = data.get("cortex_xdr_query_schema")
        if not isinstance(payload, dict):
            raise ValueError("Missing 'cortex_xdr_query_schema' root key")
        return payload

    # Convenience helpers -------------------------------------------------

    def datasets(self) -> Dict[str, Dict[str, Any]]:
        payload = self.load()
        datasets = payload.get("datasets", {})
        return dict(datasets) if isinstance(datasets, dict) else {}

    def field_map_for(self, dataset: str) -> Dict[str, Dict[str, Any]]:
        payload = self.load()
        mapping_key = self.DATASET_FIELD_MAP.get(dataset)
        if not mapping_key:
            return {}
        fields = payload.get(mapping_key, {})
        return dict(fields) if isinstance(fields, dict) else {}

    def list_fields(self, dataset: str) -> List[Dict[str, Any]]:
        fields = self.field_map_for(dataset)
        output: List[Dict[str, Any]] = []
        for name, meta in sorted(fields.items()):
            if isinstance(meta, dict):
                entry = {"name": name}
                entry.update(meta)
                output.append(entry)
        return output

    def operator_reference(self) -> Dict[str, Any]:
        payload = self.load()
        operators = payload.get("operators", {})
        return operators if isinstance(operators, dict) else {}

    def function_reference(self) -> Dict[str, Any]:
        payload = self.load()
        functions = payload.get("xql_functions") or payload.get("functions", {})
        return functions if isinstance(functions, dict) else {}

    def field_groups(self) -> Dict[str, Any]:
        payload = self.load()
        groups = payload.get("field_groups", {})
        return groups if isinstance(groups, dict) else {}

    def enum_values(self) -> Dict[str, Any]:
        payload = self.load()
        enums = payload.get("enum_values", {})
        return enums if isinstance(enums, dict) else {}

    def example_queries(self) -> Dict[str, Any]:
        payload = self.load()
        examples = payload.get("example_queries", {})
        return examples if isinstance(examples, dict) else {}

    def time_filters(self) -> Dict[str, Any]:
        """Return time filter presets and configuration from schema."""
        payload = self.load()
        time_filters = payload.get("time_filters", {})
        return time_filters if isinstance(time_filters, dict) else {}


def normalise_dataset(name: str | None, available: Iterable[str]) -> Tuple[str, List[str]]:
    """Return a valid dataset name and a record of normalisation steps."""

    available_list = [ds for ds in available]
    log: List[str] = []

    if not name:
        if available_list:
            default = available_list[0]
            log.append(f"defaulted_to:{default}")
            return default, log
        raise ValueError("No datasets available in schema")

    cleaned = name.strip().lower().replace(" ", "_")
    if cleaned in available_list:
        if cleaned != name:
            log.append(f"normalised_from:{name}->{cleaned}")
        return cleaned, log

    # Attempt fuzzy fallback by prefix
    for candidate in available_list:
        if candidate.startswith(cleaned):
            log.append(f"prefix_matched:{candidate}")
            return candidate, log

    raise ValueError(
        f"Unknown dataset '{name}'. Valid options: {', '.join(available_list)}"
    )


# Backwards compatibility for components copied from CBC implementation
CBCSchemaCache = CortexSchemaCache
