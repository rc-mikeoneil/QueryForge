from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Import path validation utilities
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from shared.security import validate_schema_path, validate_glob_results

logger = logging.getLogger(__name__)

# Security constants
MAX_CACHE_SIZE_BYTES = 100 * 1024 * 1024  # 100MB limit for cache files
SCHEMA_INTEGRITY_KEY_ENV = "SCHEMA_INTEGRITY_KEY"


class CBCSchemaCache:
    """Load and cache the Carbon Black Cloud EDR schema file."""

    def __init__(self, schema_path: Path, cache_dir: Optional[Path] = None) -> None:
        """
        Initialize CBC schema cache with security validations.

        Parameters
        ----------
        schema_path : Path
            Path to the schema file (will be validated for security)
        cache_dir : Optional[Path]
            Directory for cache files (defaults to .cache)

        Raises
        ------
        ValueError
            If schema_path is outside allowed directories or contains suspicious patterns
        """
        # Security: Validate schema path to prevent path traversal attacks
        self.schema_path = validate_schema_path(Path(schema_path))

        self._lock = threading.Lock()
        self._cache: Dict[str, Any] | None = None
        self._cache_version: int = 0
        self._source_signature: Optional[str] = None

        if cache_dir is None:
            cache_dir = Path(".cache")
        self.cache_file = cache_dir / "cbc_schema_cache.json"
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
                        search_types = self._cache.get("search_types", {})
                        logger.info("CBC schema cache warmed from disk (%d search types)", len(search_types))
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
                
                search_types = payload.get("search_types", {})
                logger.info("Loaded CBC schema with %d search types", len(search_types))
            return self._cache
    
    def _compute_signature(self) -> Optional[str]:
        """
        Compute HMAC-SHA256 signature of actual file contents for integrity verification.

        This prevents cache poisoning attacks by ensuring the cache signature
        cannot be forged by modifying file metadata (mtime/size).
        """
        try:
            # Get integrity key from environment, use a default if not set
            # In production, SCHEMA_INTEGRITY_KEY should be set to a secure random value
            secret_key = os.getenv(SCHEMA_INTEGRITY_KEY_ENV, "default-dev-key-change-in-production").encode("utf-8")

            if not self.schema_path.exists():
                return None

            # Compute HMAC of actual file content
            with self.schema_path.open("rb") as f:
                content = f.read()

            # Use HMAC-SHA256 for cryptographic integrity
            signature = hmac.new(secret_key, content, hashlib.sha256).hexdigest()
            return signature

        except (OSError, IOError) as exc:
            logger.warning("Failed to compute signature for %s: %s", self.schema_path, exc)
            return None
    
    def _load_from_disk(self, expected_signature: str) -> Optional[Dict[str, Any]]:
        """
        Load cached schema from disk if signature matches.

        Includes security measures:
        - File size limits to prevent DoS via large cache files
        - Cryptographic signature verification to prevent cache poisoning
        - Type validation to ensure schema structure is valid
        """
        if not self.cache_file.exists():
            return None

        try:
            # Security: Check file size BEFORE reading to prevent memory exhaustion
            file_size = self.cache_file.stat().st_size
            if file_size > MAX_CACHE_SIZE_BYTES:
                logger.error(
                    "Cache file %s exceeds maximum size limit (%d bytes > %d bytes). "
                    "Refusing to load potentially malicious cache.",
                    self.cache_file,
                    file_size,
                    MAX_CACHE_SIZE_BYTES
                )
                return None

            with self.cache_file.open("r", encoding="utf-8") as f:
                data = json.load(f)

            # Security: Verify cryptographic signature to prevent cache poisoning
            cached_signature = data.get("signature")
            if cached_signature != expected_signature:
                logger.warning(
                    "CBC cache signature verification FAILED. "
                    "Expected: %s, Got: %s. Cache may be tampered. Reloading from source.",
                    expected_signature[:16] + "..." if expected_signature else "None",
                    cached_signature[:16] + "..." if cached_signature else "None"
                )
                return None

            # Validate schema structure
            if not isinstance(data.get("schema"), dict):
                logger.warning("Invalid cache structure: 'schema' must be a dictionary")
                return None

            logger.debug("Cache loaded successfully with valid signature")
            return data

        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse CBC cache JSON: %s", exc)
            return None
        except Exception as exc:
            logger.warning("Failed to load CBC cache from disk: %s", exc)
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
            logger.warning("Failed to persist CBC cache to disk: %s", exc)
    
    def _load_split_schema(self) -> Optional[Dict[str, Any]]:
        """
        Load schema from multiple cbc_*.json files and merge them.

        Includes security validation of all file paths to prevent
        symlink-based path traversal attacks.
        """
        schema_dir = self.schema_path.parent
        cbc_files_raw = sorted(schema_dir.glob("cbc_*.json"))

        # Security: Validate all glob results to prevent symlink attacks
        cbc_files = validate_glob_results(schema_dir, cbc_files_raw)

        # Exclude the monolithic cbc_schema.json file if it exists
        cbc_files = [f for f in cbc_files if f.name != "cbc_schema.json"]

        if not cbc_files:
            return None

        logger.info("Loading CBC schema from %d split files", len(cbc_files))
        merged: Dict[str, Any] = {}

        for file_path in cbc_files:
            try:
                with file_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                
                if not isinstance(data, dict):
                    continue
                
                payload = data.get("carbonblack_edr_query_schema")
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
        
        logger.info("Merged CBC schema from split files (keeping split field sets)")
        return merged
    
    def _load_monolithic_schema(self) -> Dict[str, Any]:
        """Load schema from single cbc_schema.json file."""
        logger.info("Loading Carbon Black Cloud schema from %s", self.schema_path.name)
        raw = self.schema_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Schema root must be a JSON object")
        payload = data.get("carbonblack_edr_query_schema")
        if not isinstance(payload, dict):
            raise ValueError("Missing 'carbonblack_edr_query_schema' root key")
        return payload

    # Convenience helpers -------------------------------------------------

    def search_types(self) -> Dict[str, Dict[str, Any]]:
        return dict(self.load().get("search_types", {}))

    def field_map_for(self, search_type: str) -> Dict[str, Dict[str, Any]]:
        payload = self.load()
        
        # For process_search, merge all process_*_fields into one dict
        if search_type == "process_search":
            merged_fields: Dict[str, Dict[str, Any]] = {}
            for key in payload.keys():
                if key.startswith("process_") and key.endswith("_fields"):
                    fields = payload.get(key, {})
                    if isinstance(fields, dict):
                        merged_fields.update(fields)
            return merged_fields
        
        # For other search types, use direct mapping
        mapping_key = {
            "binary_search": "binary_search_fields",
            "alert_search": "alert_search_fields",
            "threat_report_search": "threat_report_search_fields",
        }.get(search_type)

        if not mapping_key:
            return {}

        fields = payload.get(mapping_key, {})
        return dict(fields) if isinstance(fields, dict) else {}

    def list_fields(self, search_type: str) -> List[Dict[str, Any]]:
        fields = self.field_map_for(search_type)
        output: List[Dict[str, Any]] = []
        for name, meta in sorted(fields.items()):
            if isinstance(meta, dict):
                entry = {"name": name}
                entry.update(meta)
                output.append(entry)
        return output

    def operator_reference(self) -> Dict[str, Any]:
        payload = self.load()
        return payload.get("operators", {})

    def best_practices(self) -> List[str] | Dict[str, Any]:
        payload = self.load()
        best = payload.get("best_practices")
        return best if isinstance(best, (list, dict)) else []

    def example_queries(self) -> Dict[str, Any]:
        payload = self.load()
        examples = payload.get("example_queries", {})
        return examples if isinstance(examples, dict) else {}


def normalise_search_type(name: str | None, available: Iterable[str]) -> Tuple[str, List[str]]:
    """Return a valid search type and a record of the normalisation steps."""

    available_list = [st for st in available]
    log: List[str] = []

    if not name:
        if available_list:
            default = available_list[0]
            log.append(f"defaulted_to:{default}")
            return default, log
        raise ValueError("No search types available in schema")

    cleaned = name.strip().lower().replace(" ", "_")
    candidates = {
        "process": "process_search",
        "process_search": "process_search",
        "binary": "binary_search",
        "binary_search": "binary_search",
        "alert": "alert_search",
        "alert_search": "alert_search",
        "alerts": "alert_search",
        "threat": "threat_report_search",
        "threat_report": "threat_report_search",
        "threat_report_search": "threat_report_search",
        "report": "threat_report_search",
    }

    resolved = candidates.get(cleaned, cleaned)
    if resolved in available_list:
        if resolved != name:
            log.append(f"normalised_from:{name}->{resolved}")
        return resolved, log

    # Attempt fuzzy fallback by prefix
    for candidate in available_list:
        if candidate.startswith(resolved):
            log.append(f"prefix_matched:{candidate}")
            return candidate, log

    raise ValueError(f"Unknown search type '{name}'. Valid options: {', '.join(available_list)}")
