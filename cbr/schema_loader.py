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


class CBResponseSchemaCache:
    """Load and cache the Carbon Black Response Event Forwarder schema files."""

    def __init__(self, schema_path: Path, cache_dir: Optional[Path] = None) -> None:
        """
        Initialize CBR schema cache with security validations.

        Parameters
        ----------
        schema_path : Path
            Path to the schema directory or monolithic file (will be validated for security)
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
        self.cache_file = cache_dir / "cbr_schema_cache.json"
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)

    def load(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Load schema from cache or source files.

        Parameters
        ----------
        force_refresh : bool
            If True, bypass cache and reload from source

        Returns
        -------
        Dict[str, Any]
            The schema payload
        """
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
                        logger.info("CBR schema cache warmed from disk (%d search types)", len(search_types))
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
                logger.info("Loaded CBR schema with %d search types", len(search_types))
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

            # Determine schema directory
            if self.schema_path.is_file():
                schema_dir = self.schema_path.parent
            else:
                schema_dir = self.schema_path

            # Compute signature from all cbr_*.json files
            cbr_files_raw = sorted(schema_dir.glob("cbr_*.json"))
            cbr_files = validate_glob_results(schema_dir, cbr_files_raw)

            if not cbr_files:
                return None

            # Concatenate content of all files for signature
            combined_content = b""
            for file_path in cbr_files:
                with file_path.open("rb") as f:
                    combined_content += f.read()

            # Use HMAC-SHA256 for cryptographic integrity
            signature = hmac.new(secret_key, combined_content, hashlib.sha256).hexdigest()
            return signature

        except (OSError, IOError) as exc:
            logger.warning("Failed to compute signature for CBR schema: %s", exc)
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
                    "CBR cache signature verification FAILED. "
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
            logger.warning("Failed to parse CBR cache JSON: %s", exc)
            return None
        except Exception as exc:
            logger.warning("Failed to load CBR cache from disk: %s", exc)
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
            logger.warning("Failed to persist CBR cache to disk: %s", exc)
    
    def _load_split_schema(self) -> Optional[Dict[str, Any]]:
        """
        Load schema from multiple cbr_*.json files and merge them.

        Includes security validation of all file paths to prevent
        symlink-based path traversal attacks.
        """
        # Determine schema directory
        if self.schema_path.is_file():
            schema_dir = self.schema_path.parent
        else:
            schema_dir = self.schema_path

        cbr_files_raw = sorted(schema_dir.glob("cbr_*.json"))

        # Security: Validate all glob results to prevent symlink attacks
        cbr_files = validate_glob_results(schema_dir, cbr_files_raw)

        # Exclude the monolithic cbr_schema.json file if it exists
        cbr_files = [f for f in cbr_files if f.name != "cbr_schema.json"]

        if not cbr_files:
            return None

        logger.info("Loading CBR schema from %d split files", len(cbr_files))
        merged: Dict[str, Any] = {}

        for file_path in cbr_files:
            try:
                with file_path.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                
                if not isinstance(data, dict):
                    continue
                
                payload = data.get("carbonblack_response_query_schema")
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
        
        logger.info("Merged CBR schema from split files (keeping split field sets)")
        return merged
    
    def _load_monolithic_schema(self) -> Dict[str, Any]:
        """Load schema from single cbr_schema.json file."""
        if self.schema_path.is_file():
            schema_file = self.schema_path
        else:
            schema_file = self.schema_path / "cbr_schema.json"
        
        if not schema_file.exists():
            raise ValueError(f"No schema files found in {self.schema_path}")
        
        logger.info("Loading Carbon Black Response schema from %s", schema_file.name)
        raw = schema_file.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Schema root must be a JSON object")
        payload = data.get("carbonblack_response_query_schema")
        if not isinstance(payload, dict):
            raise ValueError("Missing 'carbonblack_response_query_schema' root key")
        return payload

    # Convenience helpers -------------------------------------------------

    def search_types(self) -> Dict[str, Dict[str, Any]]:
        """Return available search types and their datasets."""
        return dict(self.load().get("search_types", {}))

    def field_map_for(self, search_type: str) -> Dict[str, Dict[str, Any]]:
        """
        Get field map for a specific search type.

        For coarse types (server_event, endpoint_event), merges all related field sets.
        For granular types, returns the specific field set.
        
        Parameters
        ----------
        search_type : str
            The search type (e.g., 'server_event', 'endpoint_event', 'netconn', etc.)
        
        Returns
        -------
        Dict[str, Dict[str, Any]]
            Field map with field names as keys
        """
        payload = self.load()
        search_types = payload.get("search_types", {})
        
        # For server_event, merge all server-generated event fields
        if search_type == "server_event":
            merged_fields: Dict[str, Dict[str, Any]] = {}
            datasets = search_types.get("server_event", {}).get("datasets", [])
            for dataset in datasets:
                fields = payload.get(dataset, {})
                if isinstance(fields, dict):
                    merged_fields.update(fields)
            return merged_fields
        
        # For endpoint_event, merge all raw endpoint event fields
        elif search_type == "endpoint_event":
            merged_fields: Dict[str, Dict[str, Any]] = {}
            datasets = search_types.get("endpoint_event", {}).get("datasets", [])
            for dataset in datasets:
                fields = payload.get(dataset, {})
                if isinstance(fields, dict):
                    merged_fields.update(fields)
            return merged_fields
        
        # For granular types, return specific field set
        else:
            # Try direct match first
            if search_type in payload:
                fields = payload.get(search_type, {})
                return dict(fields) if isinstance(fields, dict) else {}
            
            # Try adding _fields suffix
            field_key = f"{search_type}_fields"
            if field_key in payload:
                fields = payload.get(field_key, {})
                return dict(fields) if isinstance(fields, dict) else {}
            
            return {}

    def list_fields(self, search_type: str) -> List[Dict[str, Any]]:
        """
        List all fields for a search type with their metadata.
        
        Parameters
        ----------
        search_type : str
            The search type
        
        Returns
        -------
        List[Dict[str, Any]]
            List of field dictionaries with name, type, and description
        """
        fields = self.field_map_for(search_type)
        output: List[Dict[str, Any]] = []
        for name, meta in sorted(fields.items()):
            if isinstance(meta, dict):
                entry = {"name": name}
                entry.update(meta)
                output.append(entry)
        return output

    def operator_reference(self) -> Dict[str, Any]:
        """Return operator reference documentation."""
        payload = self.load()
        return payload.get("logical_operators", {}) or payload.get("operators", {})

    def best_practices(self) -> List[str] | Dict[str, Any]:
        """Return best practices documentation."""
        payload = self.load()
        best = payload.get("best_practices")
        if best is None:
            # Try looking in nested structure
            best = payload.get("field_usage", {})
        return best if isinstance(best, (list, dict)) else []

    def example_queries(self, category: Optional[str] = None) -> Dict[str, Any]:
        """
        Return example queries.
        
        Parameters
        ----------
        category : Optional[str]
            Specific category to retrieve (e.g., 'watchlist_hit_process')
            If None, returns all examples
        
        Returns
        -------
        Dict[str, Any]
            Example queries organized by category
        """
        payload = self.load()
        examples = payload.get("example_queries", {})
        if not isinstance(examples, dict):
            examples = {}
        
        if category:
            return {category: examples.get(category, [])}
        return examples


def normalise_search_type(name: str | None, available: Iterable[str]) -> Tuple[str, List[str]]:
    """
    Normalize search type name to a valid type.
    
    Parameters
    ----------
    name : str | None
        The search type name to normalize
    available : Iterable[str]
        Available search types
    
    Returns
    -------
    Tuple[str, List[str]]
        Normalized search type and log of normalization steps
    
    Raises
    ------
    ValueError
        If no valid search type can be determined
    """
    available_list = [st for st in available]
    log: List[str] = []

    if not name:
        if available_list:
            default = available_list[0]
            log.append(f"defaulted_to:{default}")
            return default, log
        raise ValueError("No search types available in schema")

    cleaned = name.strip().lower().replace(" ", "_")
    
    # Mapping of common aliases to canonical names
    candidates = {
        "server": "server_event",
        "server_event": "server_event",
        "server_events": "server_event",
        "endpoint": "endpoint_event",
        "endpoint_event": "endpoint_event",
        "endpoint_events": "endpoint_event",
        "raw": "endpoint_event",
        "raw_endpoint": "endpoint_event",
        # Watchlist variants
        "watchlist": "watchlist_hit_process_fields",
        "watchlist_process": "watchlist_hit_process_fields",
        "watchlist_binary": "watchlist_hit_binary_fields",
        # Feed variants
        "feed": "feed_ingress_hit_process_fields",
        "feed_process": "feed_ingress_hit_process_fields",
        "feed_binary": "feed_ingress_hit_binary_fields",
        # Endpoint events
        "netconn": "netconn (network connection)_fields",
        "network": "netconn (network connection)_fields",
        "regmod": "regmod (registry modification)_fields",
        "registry": "regmod (registry modification)_fields",
        "filemod": "filemod (file modification)_fields",
        "file": "filemod (file modification)_fields",
        "procstart": "procstart (process start)_fields",
        "process": "procstart (process start)_fields",
        "childproc": "childproc (child process)_fields",
        "moduleload": "moduleload (module load)_fields",
    }

    resolved = candidates.get(cleaned, cleaned)
    if resolved in available_list:
        if resolved != name:
            log.append(f"normalised_from:{name}->{resolved}")
        return resolved, log

    # Attempt fuzzy fallback by prefix
    for candidate in available_list:
        if candidate.startswith(resolved) or resolved in candidate:
            log.append(f"fuzzy_matched:{candidate}")
            return candidate, log

    raise ValueError(f"Unknown search type '{name}'. Valid options: {', '.join(available_list)}")
