"""Configuration management for LiteLLM embedding service."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class LiteLLMConfig:
    """Configuration for LiteLLM proxy and embedding model."""

    api_key: str
    base_url: str
    model: str = "text-embedding-3-large"
    timeout: int = 30
    max_retries: int = 3
    batch_size: int = 2048  # OpenAI's max batch size
    health_check_timeout: int = 5  # Quick timeout for health checks
    embedding_timeout: int = 60  # Timeout per batch

    @classmethod
    def from_env(cls, required: bool = False) -> Optional[LiteLLMConfig]:
        """Load configuration from environment variables.

        Parameters
        ----------
        required:
            If True, raise ValueError when credentials are missing.
            If False, return None when credentials are missing.

        Returns
        -------
        LiteLLMConfig or None
            Configuration object if credentials found, None otherwise.

        Raises
        ------
        ValueError
            If required=True and credentials are missing.
        """
        api_key = os.getenv("LITELLM_API_KEY", "").strip()
        base_url = os.getenv("LITELLM_BASE_URL", "http://0.0.0.0:4000").strip()
        model = os.getenv("LITELLM_EMBEDDING_MODEL", "text-embedding-3-large").strip()

        if not api_key:
            msg = (
                "LiteLLM API key not found. Set LITELLM_API_KEY environment variable. "
                "Falling back to RapidFuzz-based retrieval."
            )
            if required:
                raise ValueError(msg)
            logger.warning(msg)
            return None

        if not base_url:
            msg = "LITELLM_BASE_URL is empty. Using default: http://0.0.0.0:4000"
            logger.warning(msg)
            base_url = "http://0.0.0.0:4000"

        logger.info(
            "LiteLLM config loaded: base_url=%s, model=%s",
            base_url,
            model,
        )

        return cls(
            api_key=api_key,
            base_url=base_url,
            model=model,
        )

    def is_valid(self) -> bool:
        """Check if configuration has required credentials."""
        return bool(self.api_key and self.base_url and self.model)
