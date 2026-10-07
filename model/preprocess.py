import pandas as pd
import numpy as np
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------
# 1. Find all valid CSV files
# ---------------------------------------------------------

csv_files = sorted([
    f
    for f in BASE_DIR.rglob("*.csv")
    if "NIDS_" not in f.name
    and not any(
        p in f.parts
        for p in [
            "venv",
            ".venv",
            "__pycache__",
            "catboost_info",
            "cleaned_dataset"
        ]
    )
])


if not csv_files:
    raise FileNotFoundError("No valid dataset CSV file found.")


print("Dataset files found:")

for f in csv_files:
    print(f)


# ---------------------------------------------------------
# 2. Read and combine all CSV files
# ---------------------------------------------------------

dfs = []

for f in csv_files:

    try:
        temp_df = pd.read_csv(f)

        # Remove extra spaces from column names
        temp_df.columns = temp_df.columns.str.strip()

        dfs.append(temp_df)

        print(
            f"Loaded: {f.name} "
            f"({len(temp_df)} rows)"
        )

    except Exception as e:

        print(
            f"Could not read {f.name}: {e}"
        )


if not dfs:
    raise ValueError("No CSV files could be loaded.")


df = pd.concat(
    dfs,
    ignore_index=True
)


print("\nCombined dataset shape:")
print(df.shape)


# ---------------------------------------------------------
# 3. Find target / Label column
# ---------------------------------------------------------

label_cols = [
    c
    for c in df.columns
    if c.lower() == "label"
]


target_column = (
    label_cols[0]
    if label_cols
    else df.columns[-1]
)


print("\nTarget column:")
print(target_column)


# ---------------------------------------------------------
# 4. Remove infinite values and rows
#    where target is missing
# ---------------------------------------------------------

df = (
    df
    .replace(
        [np.inf, -np.inf],
        np.nan
    )
    .dropna(
        subset=[target_column]
    )
)


# ---------------------------------------------------------
# 5. Convert labels to binary classes
#
# BENIGN = 0
# Everything else = 1
# ---------------------------------------------------------

y_raw = (
    df[target_column]
    .astype(str)
    .str.strip()
)


unique_labels = y_raw.unique()

print("\nOriginal labels:")
print(unique_labels)


if "BENIGN" in y_raw.str.upper().values:

    y_mapped = np.where(
        y_raw.str.upper() == "BENIGN",
        0,
        1
    )

else:

    raise ValueError(
        "BENIGN label was not found in the dataset."
    )


# ---------------------------------------------------------
# 6. Add binary target column
# ---------------------------------------------------------

df["target"] = y_mapped


print("\nClass distribution before sampling:")
print(
    df["target"].value_counts()
)


# ---------------------------------------------------------
# 7. Create balanced dataset
#
# Maximum:
# 1000 Normal
# 1000 Attack
# Total = 2000
# ---------------------------------------------------------

df_normal = df[
    df["target"] == 0
]

df_attack = df[
    df["target"] == 1
]


print("\nAvailable samples:")
print(
    f"Normal samples : {len(df_normal)}"
)

print(
    f"Attack samples : {len(df_attack)}"
)


if len(df_normal) == 0:

    raise ValueError(
        "No BENIGN / Normal samples were found."
    )


if len(df_attack) == 0:

    raise ValueError(
        "No Attack samples were found."
    )


# Maximum number from each class
samples_per_class = 1000


normal_samples = min(
    samples_per_class,
    len(df_normal)
)

attack_samples = min(
    samples_per_class,
    len(df_attack)
)


df_normal = df_normal.sample(
    n=normal_samples,
    random_state=42
)


df_attack = df_attack.sample(
    n=attack_samples,
    random_state=42
)


# Combine both classes
df = pd.concat(
    [
        df_normal,
        df_attack
    ],
    ignore_index=True
)


# Shuffle the dataset
df = df.sample(
    frac=1,
    random_state=42
).reset_index(
    drop=True
)


# ---------------------------------------------------------
# 8. Remove target source column
# ---------------------------------------------------------

df = df.drop(
    columns=[target_column]
)


# ---------------------------------------------------------
# 9. Remove leakage / identifier columns
# ---------------------------------------------------------

leakage_cols = [
    c
    for c in df.columns
    if any(
        k in c.lower()
        for k in [
            "flow id",
            "source ip",
            "destination ip",
            "timestamp",
            "unnamed"
        ]
    )
]


if leakage_cols:

    print("\nRemoving leakage columns:")

    for col in leakage_cols:
        print(col)

    df = df.drop(
        columns=leakage_cols
    )


# ---------------------------------------------------------
# 10. Check final class distribution
# ---------------------------------------------------------

print("\nFinal class distribution:")

print(
    df["target"].value_counts()
)


# Make sure both classes exist
if df["target"].nunique() < 2:

    raise ValueError(
        "Dataset contains only one class. "
        "Both BENIGN (0) and ATTACK (1) are required."
    )


# ---------------------------------------------------------
# 11. Save cleaned dataset
# ---------------------------------------------------------

output_path = (
    BASE_DIR /
    "cleaned_dataset.csv"
)


df.to_csv(
    output_path,
    index=False
)


# ---------------------------------------------------------
# 12. Final information
# ---------------------------------------------------------

print("\n========================================")
print("Preprocessing completed successfully!")
print("========================================")

print(
    f"Saved dataset to:\n{output_path}"
)

print(
    f"\nTotal rows: {len(df)}"
)

print(
    f"Total columns: {len(df.columns)}"
)

print("\nFinal class distribution:")

print(
    df["target"].value_counts()
)