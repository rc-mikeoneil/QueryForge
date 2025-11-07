"""Embedding service for semantic retrieval using OpenAI via LiteLLM proxy."""

from __future__ import annotations

import logging
import time
from typing import List, Optional, Tuple

try:
    import openai
    from openai import OpenAI
except ImportError:  # pragma: no cover - optional dependency
    openai = None  # type: ignore[assignment]
    OpenAI = None  # type: ignore[assignment,misc]

from .config import LiteLLMConfig

logger = logging.getLogger(__name__)


class EmbeddingService:
    """Service for generating embeddings via LiteLLM proxy."""

    def __init__(self, config: LiteLLMConfig):
        """Initialize the embedding service.

        Parameters
        ----------
        config:
            LiteLLM configuration with credentials and model settings.

        Raises
        ------
        RuntimeError
            If openai package is not installed.
        """
        if openai is None or OpenAI is None:
            raise RuntimeError(
                "openai package is required for embedding service. "
                "Install it with: pip install openai"
            )

        if not config.is_valid():
            raise ValueError("Invalid LiteLLM configuration provided")

        self.config = config
        self.client = OpenAI(
            api_key=config.api_key,
            base_url=config.base_url,
            timeout=config.timeout,
            max_retries=config.max_retries,
        )
        logger.info(
            "Initialized embedding service with model=%s, base_url=%s",
            config.model,
            config.base_url,
        )

    def generate_embeddings(
        self,
        texts: List[str],
        show_progress: bool = False,
    ) -> List[List[float]]:
        """Generate embeddings for a list of texts.

        Parameters
        ----------
        texts:
            List of text strings to embed.
        show_progress:
            If True, log progress for large batches.

        Returns
        -------
        List[List[float]]
            List of embedding vectors, one per input text.

        Raises
        ------
        RuntimeError
            If the API request fails after retries.
        """
        if not texts:
            return []

        embeddings: List[List[float]] = []
        total_batches = (len(texts) + self.config.batch_size - 1) // self.config.batch_size
        start_time = time.time()

        for i in range(0, len(texts), self.config.batch_size):
            batch = texts[i : i + self.config.batch_size]
            batch_num = i // self.config.batch_size + 1

            if show_progress and total_batches > 1:
                elapsed = time.time() - start_time
                logger.info(
                    "🔄 Processing batch %d/%d (%d texts, %.1fs elapsed)",
                    batch_num,
                    total_batches,
                    len(batch),
                    elapsed,
                )

            batch_start = time.time()
            try:
                # Create client with batch-specific timeout
                response = self.client.embeddings.create(
                    model=self.config.model,
                    input=batch,
                    timeout=self.config.embedding_timeout,
                )

                # Extract embeddings in order
                batch_embeddings = [item.embedding for item in response.data]
                embeddings.extend(batch_embeddings)
                
                batch_duration = time.time() - batch_start
                if show_progress and total_batches > 1:
                    logger.info(
                        "✅ Batch %d/%d completed in %.2fs",
                        batch_num,
                        total_batches,
                        batch_duration,
                    )

            except Exception as exc:
                batch_duration = time.time() - batch_start
                logger.error(
                    "❌ Failed to generate embeddings for batch %d/%d after %.2fs: %s",
                    batch_num,
                    total_batches,
                    batch_duration,
                    exc,
                )
                raise RuntimeError(f"Embedding generation failed: {exc}") from exc

        total_duration = time.time() - start_time
        if show_progress:
            logger.info(
                "✅ Generated %d embeddings using model=%s in %.2fs",
                len(embeddings),
                self.config.model,
                total_duration,
            )

        return embeddings

    def embed_query(self, query: str) -> List[float]:
        """Generate embedding for a single query string.

        Parameters
        ----------
        query:
            Query text to embed.

        Returns
        -------
        List[float]
            Embedding vector for the query.
        """
        embeddings = self.generate_embeddings([query])
        return embeddings[0] if embeddings else []

    def health_check(self) -> Tuple[bool, Optional[str]]:
        """Check if the embedding service is available.

        Returns
        -------
        Tuple[bool, Optional[str]]
            (is_healthy, error_message)
        """
        start_time = time.time()
        try:
            logger.info("🔍 Running embedding service health check (timeout=%ds)...", self.config.health_check_timeout)
            
            # Create a temporary client with aggressive timeout for health check
            health_client = OpenAI(
                api_key=self.config.api_key,
                base_url=self.config.base_url,
                timeout=self.config.health_check_timeout,
                max_retries=0,  # No retries for health check
            )
            
            # Try to embed a simple test string
            response = health_client.embeddings.create(
                model=self.config.model,
                input=["health check"],
            )
            
            if response.data and len(response.data) > 0 and response.data[0].embedding:
                duration = time.time() - start_time
                logger.info("✅ Embedding service health check passed (%.2fs)", duration)
                return True, None
            else:
                duration = time.time() - start_time
                msg = f"Health check returned empty embedding after {duration:.2f}s"
                logger.warning("⚠️ %s", msg)
                return False, msg
                
        except Exception as exc:
            duration = time.time() - start_time
            msg = f"Health check failed after {duration:.2f}s: {exc}"
            logger.warning("❌ %s", msg)
            return False, msg


def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    """Calculate cosine similarity between two vectors.

    Parameters
    ----------
    vec1, vec2:
        Input vectors of the same dimension.

    Returns
    -------
    float
        Cosine similarity score between -1 and 1.
        Higher values indicate greater similarity.
    """
    if not vec1 or not vec2:
        return 0.0

    if len(vec1) != len(vec2):
        raise ValueError(
            f"Vector dimension mismatch: {len(vec1)} != {len(vec2)}"
        )

    dot_product = sum(a * b for a, b in zip(vec1, vec2))
    norm1 = sum(a * a for a in vec1) ** 0.5
    norm2 = sum(b * b for b in vec2) ** 0.5

    if norm1 == 0.0 or norm2 == 0.0:
        return 0.0

    return dot_product / (norm1 * norm2)


def create_embedding_service(
    config: Optional[LiteLLMConfig] = None,
) -> Optional[EmbeddingService]:
    """Create an embedding service instance if configuration is available.

    Parameters
    ----------
    config:
        Optional LiteLLM configuration. If None, loads from environment.

    Returns
    -------
    EmbeddingService or None
        Service instance if configuration is valid, None otherwise.
    """
    if config is None:
        config = LiteLLMConfig.from_env(required=False)

    if config is None:
        logger.info("No LiteLLM configuration available, embeddings disabled")
        return None

    try:
        service = EmbeddingService(config)
        is_healthy, error = service.health_check()
        if not is_healthy:
            logger.warning(
                "Embedding service health check failed: %s. Using fallback.",
                error,
            )
            return None
        return service
    except Exception as exc:
        logger.warning(
            "Failed to initialize embedding service: %s. Using fallback.",
            exc,
        )
        return None
