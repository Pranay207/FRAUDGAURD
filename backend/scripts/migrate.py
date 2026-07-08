from app.db import apply_migrations, init_db


if __name__ == "__main__":
    apply_migrations()
    init_db()
    print("FraudGuard migrations applied successfully.")
