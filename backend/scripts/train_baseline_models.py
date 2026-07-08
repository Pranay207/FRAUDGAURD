from app.services.training import train_baseline_models


if __name__ == "__main__":
    artifacts = train_baseline_models()
    print("FraudGuard baseline models trained:")
    for name, path in artifacts.items():
        print(f"- {name}: {path}")
