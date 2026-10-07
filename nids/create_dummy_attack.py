import joblib
import pandas as pd
import numpy as np
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE_DIR / "model" / "xgboost_nids_model.pkl"
DATASET_PATH = BASE_DIR / "model" / "cleaned_dataset.csv"
OUTPUT_PATH = BASE_DIR / "nids" / "dummy_malicious_traffic.csv"


# ============================================================
# LOAD MODEL ARTIFACT
# ============================================================

print("\nLoading NIDS model...")

artifacts = joblib.load(MODEL_PATH)

model = artifacts["model"]
train_columns = artifacts["train_columns"]
selected_features = artifacts["selected_features"]
medians = artifacts["medians"]

print("NIDS model loaded successfully.")

print("\nSelected features:")

for feature in selected_features:
    print(f"- {feature}")


# ============================================================
# LOAD DATASET
# ============================================================

print("\nLoading CICIDS2017 cleaned dataset...")

df = pd.read_csv(DATASET_PATH)

df.columns = df.columns.str.strip()

print(
    f"Dataset contains "
    f"{len(df)} rows."
)


# ============================================================
# FIND ATTACK ROWS
# ============================================================

attack_rows = df[
    df["target"] == 1
].copy()

if attack_rows.empty:

    raise ValueError(
        "No attack rows found in dataset."
    )

print(
    f"\nFound {len(attack_rows)} attack rows."
)


# ============================================================
# FIND AN ATTACK THAT MODEL DETECTS
# ============================================================

print(
    "\nSearching for an attack sample "
    "that the model correctly detects..."
)

found_row = None

for index, row in attack_rows.iterrows():

    # Build complete training feature set
    test_data = pd.DataFrame(
        [[
            row.get(
                feature,
                medians.get(feature, 0)
            )
            for feature in train_columns
        ]],
        columns=train_columns
    )

    # Numeric conversion
    test_data = test_data.apply(
        pd.to_numeric,
        errors="coerce"
    )

    # Replace infinity
    test_data = test_data.replace(
        [np.inf, -np.inf],
        np.nan
    )

    # Fill missing values
    test_data = test_data.fillna(medians)

    # Apply variance selection
    variance_data = artifacts[
        "variance_selector"
    ].transform(test_data)

    variance_features = [
        column
        for column, keep
        in zip(
            train_columns,
            artifacts[
                "variance_selector"
            ].get_support()
        )
        if keep
    ]

    variance_data = pd.DataFrame(
        variance_data,
        columns=variance_features
    )

    # Remove highly correlated features
    corr_data = variance_data.drop(
        columns=artifacts[
            "high_corr_features"
        ],
        errors="ignore"
    )

    # Select final 15 features
    final_data = corr_data[
        selected_features
    ]

    # Predict
    prediction = model.predict(
        final_data
    )[0]

    if prediction == 1:

        found_row = row.copy()

        print(
            f"\n✓ Attack sample found "
            f"at dataset row {index}"
        )

        break


# ============================================================
# CHECK
# ============================================================

if found_row is None:

    raise RuntimeError(
        "Could not find a correctly "
        "detected attack sample."
    )


# ============================================================
# CREATE COMPLETE DUMMY TRAFFIC
# ============================================================

dummy_data = {}


# Network information
dummy_data["source_ip"] = "10.0.0.50"
dummy_data["destination_ip"] = "192.168.1.10"
dummy_data["source_port"] = 4444
dummy_data["protocol"] = "TCP"


# Add ALL features required by detector
for feature in train_columns:

    if feature in found_row.index:

        value = found_row[feature]

    else:

        value = medians.get(
            feature,
            0
        )

    dummy_data[feature] = value


# Create DataFrame
dummy_df = pd.DataFrame(
    [dummy_data]
)


# ============================================================
# SAVE DUMMY FILE
# ============================================================

dummy_df.to_csv(
    OUTPUT_PATH,
    index=False
)


# ============================================================
# DISPLAY RESULT
# ============================================================

print("\n")
print("=" * 60)

print(
    "DUMMY MALICIOUS TRAFFIC CREATED"
)

print("=" * 60)

print(
    f"\nSaved to:"
)

print(
    OUTPUT_PATH
)

print(
    f"\nTotal columns: "
    f"{len(dummy_df.columns)}"
)

print(
    f"Required model features: "
    f"{len(train_columns)}"
)

print(
    "\n✓ The dummy file now contains "
    "the complete feature set required "
    "by detector.py."
)

print("=" * 60)