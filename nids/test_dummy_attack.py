import sys
from pathlib import Path


# ============================================================
# PROJECT ROOT
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))


# ============================================================
# IMPORTS
# ============================================================

import pandas as pd

from nids.detector import detect
from nids.database_logger import save_detection


# ============================================================
# DUMMY FILE
# ============================================================

DUMMY_FILE = (
    BASE_DIR
    / "nids"
    / "dummy_malicious_traffic.csv"
)


# ============================================================
# START
# ============================================================

print("\n")
print("=" * 60)
print("NIDS DUMMY MALICIOUS TRAFFIC TEST")
print("=" * 60)


# ============================================================
# CHECK FILE
# ============================================================

if not DUMMY_FILE.exists():

    print(
        "\n[ERROR] Dummy attack file not found."
    )

    print(
        "\nRun this first:"
    )

    print(
        "python nids\\create_dummy_attack.py"
    )

    sys.exit(1)


# ============================================================
# LOAD FILE
# ============================================================

print(
    "\nLoading dummy malicious traffic..."
)

df = pd.read_csv(
    DUMMY_FILE
)

if df.empty:

    print(
        "\n[ERROR] Dummy file is empty."
    )

    sys.exit(1)


row = df.iloc[0]

print(
    "Dummy attack loaded successfully."
)


# ============================================================
# SEPARATE NETWORK INFORMATION
# ============================================================

source_ip = str(
    row["source_ip"]
)

destination_ip = str(
    row["destination_ip"]
)

source_port = int(
    row["source_port"]
)

protocol = str(
    row["protocol"]
)


# ============================================================
# CREATE FEATURE DICTIONARY
# ============================================================

metadata_columns = [
    "source_ip",
    "destination_ip",
    "source_port",
    "protocol"
]

features = {}

for column in df.columns:

    if column in metadata_columns:
        continue

    value = row[column]

    try:

        value = float(value)

    except (ValueError, TypeError):

        value = 0.0

    features[column] = value


# ============================================================
# DISPLAY TRAFFIC
# ============================================================

print("\n")
print("=" * 60)
print("DUMMY MALICIOUS TRAFFIC")
print("=" * 60)

print(
    f"\nSource IP       : {source_ip}"
)

print(
    f"Source Port     : {source_port}"
)

print(
    f"Destination IP  : {destination_ip}"
)

print(
    f"Protocol        : {protocol}"
)

print(
    f"Destination Port: "
    f"{int(features.get('Destination Port', 0))}"
)


# ============================================================
# RUN DETECTOR
# ============================================================

print("\n")
print("=" * 60)
print("RUNNING NIDS DETECTOR")
print("=" * 60)


try:

    result = detect(
        features
    )

except Exception as e:

    print(
        "\n[DETECTION ERROR]"
    )

    print(e)

    print(
        f"\nError type: "
        f"{type(e).__name__}"
    )

    sys.exit(1)


# ============================================================
# DISPLAY RESULT
# ============================================================

print("\n")
print("=" * 60)
print("NIDS DETECTION RESULT")
print("=" * 60)

print(
    f"\nSource      : "
    f"{source_ip}:{source_port}"
)

print(
    f"Destination : "
    f"{destination_ip}:"
    f"{int(features.get('Destination Port', 0))}"
)

print(
    f"Protocol    : {protocol}"
)

print(
    f"\nPrediction  : "
    f"{result['prediction']}"
)

print(
    f"Normal Prob : "
    f"{result['normal_probability']}%"
)

print(
    f"Attack Prob : "
    f"{result['attack_probability']}%"
)

print(
    f"Risk Score  : "
    f"{result['risk_score']}"
)

print(
    f"Severity    : "
    f"{result['severity']}"
)

print("=" * 60)


# ============================================================
# DATABASE VALUES
# ============================================================

flow_duration = features.get(
    "Flow Duration",
    0
)

total_fwd = features.get(
    "Total Length of Fwd Packets",
    0
)

total_bwd = features.get(
    "Total Length of Bwd Packets",
    0
)

total_bytes = int(
    total_fwd + total_bwd
)

packet_count = int(
    features.get(
        "Total Fwd Packets",
        10
    )
)


# ============================================================
# SAVE TO DATABASE
# ============================================================

print(
    "\nSaving detection to Neon PostgreSQL..."
)


try:

    save_detection(

        source_ip=source_ip,

        destination_ip=destination_ip,

        source_port=source_port,

        destination_port=int(
            features.get(
                "Destination Port",
                0
            )
        ),

        protocol=protocol,

        packet_count=packet_count,

        flow_duration=float(
            flow_duration
        ),

        total_bytes=total_bytes,

        result=result
    )


except Exception as e:

    print(
        "\n[DATABASE ERROR]"
    )

    print(e)

    print(
        f"\nError type: "
        f"{type(e).__name__}"
    )

    sys.exit(1)


# ============================================================
# FINAL RESULT
# ============================================================

print("\n")
print("=" * 60)

if result["prediction"] == "Attack":

    print(
        "✓ ATTACK SUCCESSFULLY DETECTED"
    )

    print(
        "\nDummy malicious traffic "
        "was detected by XGBoost."
    )

    print(
        "\nDetection saved to "
        "Neon PostgreSQL."
    )

    print(
        "\nCheck your website:"
    )

    print(
        "1. Dashboard"
    )

    print(
        "2. Alerts"
    )

    print(
        "3. SHAP Explanation"
    )

    print(
        "4. Logs"
    )

else:

    print(
        "⚠ TRAFFIC CLASSIFIED AS NORMAL"
    )

    print(
        "\nThe selected attack sample "
        "was classified as normal."
    )

print("=" * 60)