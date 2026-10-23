
import sys
from pathlib import Path
from getpass import getpass

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
from app import app
from nids.db import User


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
    print("\n[ERROR] Dummy attack file not found.")
    print("\nRun this first:")
    print("python nids\\create_dummy_attack.py")
    sys.exit(1)


# ============================================================
# LOAD FILE
# ============================================================

print("\nLoading dummy malicious traffic...")

df = pd.read_csv(DUMMY_FILE)

if df.empty:
    print("\n[ERROR] Dummy file is empty.")
    sys.exit(1)

row = df.iloc[0]

print("Dummy attack loaded successfully.")


# ============================================================
# SEPARATE NETWORK INFORMATION
# ============================================================

source_ip = str(row["source_ip"])
destination_ip = str(row["destination_ip"])
source_port = int(row["source_port"])
protocol = str(row["protocol"])


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

print(f"\nSource IP       : {source_ip}")
print(f"Source Port     : {source_port}")
print(f"Destination IP  : {destination_ip}")
print(f"Protocol        : {protocol}")
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
    result = detect(features)

except Exception as e:
    print("\n[DETECTION ERROR]")
    print(e)
    print(f"\nError type: {type(e).__name__}")
    sys.exit(1)


# ============================================================
# DISPLAY RESULT
# ============================================================

print("\n")
print("=" * 60)
print("NIDS DETECTION RESULT")
print("=" * 60)

print(f"\nSource      : {source_ip}:{source_port}")
print(
    f"Destination : {destination_ip}:"
    f"{int(features.get('Destination Port', 0))}"
)
print(f"Protocol    : {protocol}")
print(f"\nPrediction  : {result['prediction']}")
print(f"Normal Prob : {result['normal_probability']}%")
print(f"Attack Prob : {result['attack_probability']}%")
print(f"Risk Score  : {result['risk_score']}")
print(f"Severity    : {result['severity']}")
print("=" * 60)


# ============================================================
# DATABASE VALUES
# ============================================================

flow_duration = features.get("Flow Duration", 0)

total_fwd = features.get(
    "Total Length of Fwd Packets", 0
)

total_bwd = features.get(
    "Total Length of Bwd Packets", 0
)

total_bytes = int(total_fwd + total_bwd)

packet_count = int(
    features.get("Total Fwd Packets", 10)
)


# ============================================================
# FIND REGISTERED USER AND SAVE
# ============================================================

print("\n")
print("=" * 60)
print("SAVING DETECTION TO NEON POSTGRESQL")
print("=" * 60)

# Enter the username you normally use to log in to NIDS.
TEST_USERNAME = input(
    "\nEnter your registered NIDS username: "
).strip()

if not TEST_USERNAME:
    print("\n[ERROR] Username cannot be empty.")
    sys.exit(1)

try:
    with app.app_context():

        test_user = User.query.filter_by(
            username=TEST_USERNAME
        ).first()

        if test_user is None:
            print(
                f"\n[ERROR] User '{TEST_USERNAME}' "
                "was not found in the configured database."
            )
            print(
                "Check your username and DATABASE_URL."
            )
            sys.exit(1)

        print(
            f"\nUser found: {test_user.username}"
        )

        save_detection(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=int(
                features.get("Destination Port", 0)
            ),
            protocol=protocol,
            packet_count=packet_count,
            flow_duration=float(flow_duration),
            total_bytes=total_bytes,
            result=result,
            user_id=test_user.id,
            app=app
        )

        print("\nSave function completed.")
        print(
            "Check the database logger output above "
            "to confirm the transaction was committed."
        )

except Exception as e:
    print("\n[DATABASE ERROR]")
    print(e)
    print(f"\nError type: {type(e).__name__}")
    sys.exit(1)


# ============================================================
# FINAL RESULT
# ============================================================

print("\n")
print("=" * 60)

if result["prediction"] == "Attack":
    print("✓ ATTACK CLASSIFIED BY THE MODEL")
    print("\nDummy traffic was classified as an attack.")
    print("\nCheck your website:")
    print("1. Dashboard")
    print("2. Alerts")
    print("3. SHAP Explanation")
    print("4. Logs")
else:
    print("⚠ TRAFFIC CLASSIFIED AS NORMAL")
    print(
        "\nThe selected dummy sample was classified "
        "as normal."
    )

print("=" * 60)
