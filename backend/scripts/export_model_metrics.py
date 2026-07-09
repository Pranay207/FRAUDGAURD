import json
from datetime import UTC, datetime
from pathlib import Path

from app.config import get_settings
from app.services.training import train_baseline_models


def main() -> None:
    settings = get_settings()
    results = train_baseline_models()
    project_root = Path(__file__).resolve().parents[2]
    report_path = project_root / "MODEL_EVALUATION_SUMMARY.json"
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "training_manifest": {
            "mode": "script_export",
            "source": "backend/scripts/export_model_metrics.py",
        },
        "models": {
            model_name: {
                "version_id": info["version_id"],
                "artifact_path": info["artifact_path"],
                "metrics": info["metrics"],
            }
            for model_name, info in sorted(results.items())
        },
    }
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(report_path)


if __name__ == "__main__":
    main()
