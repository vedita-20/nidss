
import joblib
import pandas as pd
import numpy as np
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    BASE_DIR
    / "model"
    / "xgboost_nids_model.pkl"
)

DATASET_PATH = (
    BASE_DIR
    / "model"
    / "cleaned_dataset.csv"
)


# ============================================================
# LOAD MODEL
# ============================================================

print("\nLoading NIDS model...")

artifacts = joblib.load(MODEL_PATH)

model = artifacts["model"]

selected_features = artifacts["selected_features"]

medians = artifacts["medians"]


print("Model loaded successfully.")


# ============================================================
# LOAD DATASET
# ============================================================

print("\nLoading CICIDS2017 cleaned dataset...")

df = pd.read_csv(DATASET_PATH)

df.columns = df.columns.str.strip()


# ============================================================
# FIND ATTACK ROWS
# ============================================================

attack_rows = df[
    df["target"] == 1
].copy()


if attack_rows.empty:

    raise ValueError(
        "No attack rows (target=1) found "
        "in cleaned_dataset.csv."
    )


print(
    f"\nFound {len(attack_rows)} attack rows."
)


# ============================================================
# SELECT ONE REAL ATTACK ROW
# ============================================================

attack_row = attack_rows.iloc[0]


# ============================================================
# EXTRACT MODEL FEATURES
# ============================================================

test_data = pd.DataFrame(
    [[
        attack_row.get(
            feature,
            medians.get(feature, 0)
        )
        for feature in selected_features
    ]],
    columns=selected_features
)


# Convert to numeric

test_data = test_data.apply(
    pd.to_numeric,
    errors="coerce"
)


test_data = test_data.replace(
    [np.inf, -np.inf],
    np.nan
)


test_data = test_data.fillna(
    medians
)


# ============================================================
# DISPLAY TEST DATA
# ============================================================

print("\n")
print("=" * 60)

print("REAL ATTACK SAMPLE FROM CICIDS2017")

print("=" * 60)

print(
    test_data.to_string(
        index=False
    )
)


# ============================================================
# RUN MODEL
# ============================================================

print("\n")
print("=" * 60)

print("RUNNING NIDS DETECTOR")

print("=" * 60)


prediction = model.predict(
    test_data
)[0]


probabilities = model.predict_proba(
    test_data
)[0]


normal_probability = (
    probabilities[0] * 100
)

attack_probability = (
    probabilities[1] * 100
)


# ============================================================
# RESULT
# ============================================================

if prediction == 1:

    result = "ATTACK"

else:

    result = "NORMAL"


print("\nPrediction:")
print(result)


print(
    f"\nNormal Probability : "
    f"{normal_probability:.2f}%"
)


print(
    f"Attack Probability : "
    f"{attack_probability:.2f}%"
)


# ============================================================
# RISK
# ============================================================

risk_score = attack_probability


if risk_score >= 80:

    severity = "High"

elif risk_score >= 50:

    severity = "Medium"

else:

    severity = "Low"


print(
    f"\nRisk Score : "
    f"{risk_score:.2f}"
)


print(
    f"Severity   : "
    f"{severity}"
)


print("\n" + "=" * 60)


# ============================================================
# FINAL MESSAGE
# ============================================================

if prediction == 1:

    print(
        "\n✓ SUCCESS!"
    )

    print(
        "The trained XGBoost model "
        "correctly detected the real "
        "CICIDS2017 attack sample."
    )

else:

    print(
        "\n⚠ The selected attack row "
        "was classified as NORMAL."
    )

    print(
        "We will test additional attack "
        "rows instead of changing the model."
    )


print("=" * 60)

