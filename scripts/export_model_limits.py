"""Export the limits of the models for the console.

    python scripts/export_model_limits.py --out web/src/generated/model-limits.json

The console shows the tokens every model used today next to the limits the
engine enforces on it. The gateway does not carry the registry, so the limits
are exported here into a small file that the bundle imports.

The file holds no key and no secret: only the model ids and their limits.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from oracle_hcm.config.models import load_model_registry
from oracle_hcm.paths import config_dir


def collect(path: Path) -> dict[str, object]:
    """The limits of every model of the registry."""
    registry = load_model_registry(path)
    models: dict[str, dict[str, object]] = {}
    for role, spec in registry.roles.items():
        for candidate in spec.configured_candidates():
            limits = spec.limits_for(candidate)
            entry = models.setdefault(
                candidate,
                {"model": candidate, "roles": [], "rpm": limits.rpm, "tpm": limits.tpm},
            )
            roles = entry["roles"]
            if isinstance(roles, list) and role.value not in roles:
                roles.append(role.value)
    return {
        "source": str(path.name),
        "models": [models[name] for name in sorted(models)],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=str(config_dir() / "models.yaml"))
    parser.add_argument("--out", required=True)
    arguments = parser.parse_args()
    payload = collect(Path(arguments.config))
    target = Path(arguments.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    models = payload.get("models")
    count = len(models) if isinstance(models, list) else 0
    print(f"wrote {count} model(s) to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
