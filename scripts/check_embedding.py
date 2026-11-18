"""Live check of the embedding model of the configuration.

    python scripts/check_embedding.py

The script embeds one short sentence with the model of the "embeddings"
section of config/models.yaml and prints the length of the vector and the
latency of the call. It never prints the key and never prints the text that
was sent. It is not part of the test suite: it reaches the provider.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# The cost map of LiteLLM is fetched from the network on every start, which
# only adds noise here: the local copy is enough.
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

from oracle_hcm.config.env import load_env
from oracle_hcm.config.models import load_model_registry
from oracle_hcm.errors import ConfigurationError, MissingApiKeyError
from oracle_hcm.knowledge.litellm_embedding import build_embedder

SENTENCE = "The attendance of an employee is recorded from the punches of a day."


def main() -> int:
    """Embed one sentence and report the length and the latency."""
    load_env()
    try:
        spec = load_model_registry().require_embeddings()
    except ConfigurationError as exc:
        print(f"the embedding model is not configured: {exc}")
        return 1
    embedder = build_embedder(spec)
    try:
        started = time.monotonic()
        vectors = embedder.embed([SENTENCE])
        latency_ms = int((time.monotonic() - started) * 1000)
    except MissingApiKeyError:
        print("no API key in the environment for the provider of the model")
        return 1
    except ConfigurationError as exc:
        print(f"the embedding model is not configured: {exc}")
        return 1
    except Exception as exc:
        print(f"the embedding call failed: {type(exc).__name__}: {exc}")
        return 1
    print(f"vector_length: {len(vectors[0])}")
    print(f"latency_ms: {latency_ms}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
