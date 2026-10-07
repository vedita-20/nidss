import pandas as pd
from pathlib import Path

from detector import detect
from explainable_ai import explain_prediction


# Project root
BASE_DIR = Path(__file__).resolve().parent.parent

# Dataset path
DATASET_PATH = (
    BASE_DIR
    / "model"
    / "cleaned_dataset.csv"
)


# Load dataset
df = pd.read_csv(DATASET_PATH)

# Remove target column if present
features_df = df.drop(
    columns=["target"],
    errors="ignore"
)

# Take first row
row = features_df.iloc[0]

# Run NIDS detection
result = detect(row)

print("\nPrediction:", result["prediction"])
print("Confidence:", result["confidence"])
print("Risk Score:", result["risk_score"])


# Generate SHAP explanation
explanations = explain_prediction(
    result["features"]
)


print("\n" + "=" * 70)
print("SHAP EXPLANATION")
print("=" * 70)

for explanation in explanations:

    print(
        f"{explanation['feature_name']}: "
        f"SHAP={explanation['shap_value']:.4f} | "
        f"Contribution={explanation['contribution']}"
    )

print("=" * 70)