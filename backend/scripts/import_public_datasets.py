from __future__ import annotations

import argparse
import shutil
from pathlib import Path


DEFAULT_CREDITCARD_SOURCE = Path(r"C:\Users\Shiva\Downloads\archive (1)\creditcard.csv")
DEFAULT_PHISHING_SOURCE = Path(r"C:\Users\Shiva\Downloads\phishing+websites\Training Dataset.arff")


def main() -> None:
    parser = argparse.ArgumentParser(description="Import external fraud datasets into backend/data/raw.")
    parser.add_argument("--creditcard", type=Path, default=DEFAULT_CREDITCARD_SOURCE)
    parser.add_argument("--phishing", type=Path, default=DEFAULT_PHISHING_SOURCE)
    parser.add_argument("--output-dir", type=Path, default=Path("data/raw"))
    args = parser.parse_args()

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    copied.extend(_copy_if_present(args.creditcard, output_dir / "creditcard.csv"))
    copied.extend(_copy_if_present(args.phishing, output_dir / "phishing_websites.arff"))

    if copied:
        print("Imported datasets:")
        for line in copied:
            print(f"- {line}")
    else:
        print("No dataset files were imported. Check the source paths and try again.")


def _copy_if_present(source: Path, destination: Path) -> list[str]:
    if not source.exists():
        return []
    shutil.copy2(source, destination)
    return [f"{source} -> {destination}"]


if __name__ == "__main__":
    main()
