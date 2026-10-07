import sys
from pathlib import Path

# -----------------------------------
# PROJECT ROOT
# -----------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# -----------------------------------
# IMPORTS
# -----------------------------------

import pandas as pd

from nids.detector import detect
from nids.database_logger import save_detection


# -----------------------------------
# DATASET PATH
# -----------------------------------

DATASET_PATH = (
    PROJECT_ROOT
    / "model"
    / "cleaned_dataset.csv"
)


# -----------------------------------
# LOAD DATASET
# -----------------------------------

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

print(f"Dataset loaded: {len(df)} rows")


# -----------------------------------
# SHOW DATASET COLUMNS
# -----------------------------------

print("\nDataset columns:")
print(df.columns.tolist())


# -----------------------------------
# SELECT ONE SAMPLE
# -----------------------------------

sample = df.iloc[0]


# -----------------------------------
# CONVERT SAMPLE TO DICTIONARY
# -----------------------------------

features = sample.to_dict()


# -----------------------------------
# REMOVE TARGET COLUMN
# -----------------------------------

# Your cleaned dataset uses "target"
# as the target/label column.

features.pop("target", None)

# Also handle "Label" if it exists
features.pop("Label", None)


# -----------------------------------
# RUN XGBOOST DETECTION
# -----------------------------------

print("\nRunning XGBoost detection...")

result = detect(features)


# -----------------------------------
# DISPLAY RESULT
# -----------------------------------

print("\n" + "=" * 60)
print("DATABASE INTEGRATION TEST")
print("=" * 60)

print(f"Prediction         : {result['prediction']}")
print(f"Confidence         : {result['confidence']}")
print(f"Normal Probability : {result['normal_probability']}")
print(f"Attack Probability : {result['attack_probability']}")
print(f"Risk Score         : {result['risk_score']}")
print(f"Severity           : {result['severity']}")

print("=" * 60)


# -----------------------------------
# SAVE DETECTION
# -----------------------------------

print("\nSaving detection to Neon...")

save_detection(
    source_ip="192.168.1.100",
    destination_ip="8.8.8.8",
    source_port=54321,
    destination_port=443,
    protocol="TCP",
    packet_count=10,
    flow_duration=1.25,
    total_bytes=5000,
    result=result
)


# -----------------------------------
# COMPLETE
# -----------------------------------

print("\n" + "=" * 60)
print("DATABASE TEST COMPLETED")
print("=" * 60)