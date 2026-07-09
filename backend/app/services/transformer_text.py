from __future__ import annotations

import json
from pathlib import Path


class TransformerTextClassifier:
    def __init__(self, artifact_path: Path | str) -> None:
        self.artifact_path = Path(artifact_path)
        self._tokenizer = None
        self._model = None
        self._torch = None

    def _load(self) -> bool:
        if self._model is not None and self._tokenizer is not None and self._torch is not None:
            return True
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError:
            return False
        if not self.artifact_path.exists() or not self.artifact_path.is_dir():
            return False
        self._tokenizer = AutoTokenizer.from_pretrained(self.artifact_path)
        self._model = AutoModelForSequenceClassification.from_pretrained(self.artifact_path)
        self._model.eval()
        self._torch = torch
        return True

    def predict_proba(self, texts: list[str]):
        if not self._load():
            raise RuntimeError("Transformer text classifier dependencies or artifacts are unavailable")
        assert self._tokenizer is not None and self._model is not None and self._torch is not None
        batch = self._tokenizer(texts, padding=True, truncation=True, max_length=128, return_tensors="pt")
        with self._torch.no_grad():
            logits = self._model(**batch).logits
            probabilities = self._torch.softmax(logits, dim=1)
        return probabilities.cpu().numpy()


def write_transformer_metadata(artifact_path: Path | str, payload: dict) -> None:
    path = Path(artifact_path)
    path.mkdir(parents=True, exist_ok=True)
    (path / "fraudguard_transformer_meta.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
