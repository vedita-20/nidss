import time
import joblib
import pandas as pd
import numpy as np
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.feature_selection import VarianceThreshold, mutual_info_classif
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
    log_loss
)

from xgboost import XGBClassifier


# ============================================================
# 1. PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

dataset_path = BASE_DIR / "cleaned_dataset.csv"
model_path = BASE_DIR / "xgboost_nids_model.pkl"


# ============================================================
# 2. CHECK DATASET
# ============================================================

if not dataset_path.exists():
    raise FileNotFoundError(
        "cleaned_dataset.csv not found.\n"
        "Run preprocess.py first."
    )

print("Using dataset:")
print(dataset_path)


# ============================================================
# 3. LOAD DATASET
# ============================================================

df = pd.read_csv(dataset_path)

df.columns = df.columns.str.strip()

print("\nDataset shape:")
print(df.shape)


# ============================================================
# 4. CHECK TARGET
# ============================================================

if "target" not in df.columns:
    raise ValueError(
        "Target column 'target' was not found "
        "in cleaned_dataset.csv."
    )

y = df["target"]

X = df.drop(columns=["target"])


print("\nTarget column:")
print("target")


print("\nClass distribution:")
print(y.value_counts())


# ============================================================
# 5. CHECK FOR BOTH CLASSES
# ============================================================

if y.nunique() < 2:
    raise ValueError(
        "Only one class is present in the dataset.\n"
        "XGBoost requires both Normal (0) and Attack (1).\n"
        "Run preprocess.py again."
    )


# ============================================================
# 6. CONVERT FEATURES TO NUMERIC
# ============================================================

X = X.apply(pd.to_numeric, errors="coerce")

X = X.replace(
    [np.inf, -np.inf],
    np.nan
)

# Remove columns that contain only NaN
X = X.dropna(
    axis=1,
    how="all"
)


# ============================================================
# 7. TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=114,
    random_state=42,
    stratify=y
)


print("\nTraining samples:")
print(len(X_train))

print("Testing samples:")
print(len(X_test))


# ============================================================
# 8. SAVE TRAINING COLUMN INFORMATION
# ============================================================

train_columns = X.columns.tolist()


# ============================================================
# 9. HANDLE MISSING VALUES
# ============================================================

# IMPORTANT:
# Medians are calculated only from training data.

train_medians = X_train.median()

X_train = X_train.fillna(train_medians)

X_test = X_test.fillna(train_medians)


# ============================================================
# 10. REMOVE ZERO-VARIANCE FEATURES
# ============================================================

vt = VarianceThreshold(
    threshold=0.0
)

X_train_v = vt.fit_transform(X_train)

X_test_v = vt.transform(X_test)


# Get feature names that survived variance filtering

variance_features = X_train.columns[
    vt.get_support()
].tolist()


X_train_v = pd.DataFrame(
    X_train_v,
    columns=variance_features,
    index=X_train.index
)

X_test_v = pd.DataFrame(
    X_test_v,
    columns=variance_features,
    index=X_test.index
)


# ============================================================
# 11. REMOVE HIGHLY CORRELATED FEATURES
# ============================================================

corr = X_train_v.corr().abs()

upper = corr.where(
    np.triu(
        np.ones(corr.shape),
        k=1
    ).astype(bool)
)


high_corr = [
    column
    for column in upper.columns
    if any(
        upper[column] > 0.95
    )
]


if high_corr:

    print("\nRemoving highly correlated features:")

    for feature in high_corr:
        print(feature)


X_train_c = X_train_v.drop(
    columns=high_corr
)

X_test_c = X_test_v.drop(
    columns=high_corr
)


# ============================================================
# 12. MUTUAL INFORMATION FEATURE SELECTION
# ============================================================

print("\nCalculating feature importance...")

mi = mutual_info_classif(
    X_train_c,
    y_train,
    random_state=42
)


mi_df = pd.DataFrame({
    "Feature": X_train_c.columns,
    "MI": mi
})


mi_df = mi_df.sort_values(
    by="MI",
    ascending=False
)


# Select top 15 features

top_features = (
    mi_df
    .head(
        min(
            15,
            X_train_c.shape[1]
        )
    )["Feature"]
    .tolist()
)


print("\nSelected Top 15 Features:")

for i, feature in enumerate(
    top_features,
    start=1
):
    print(
        f"{i}. {feature}"
    )


# ============================================================
# 13. CREATE FINAL TRAINING DATA
# ============================================================

X_train_sel = X_train_c[
    top_features
]

X_test_sel = X_test_c[
    top_features
]


print("\nFinal training feature shape:")
print(X_train_sel.shape)

print("\nFinal testing feature shape:")
print(X_test_sel.shape)


# ============================================================
# 14. CREATE XGBOOST MODEL
# ============================================================

model = XGBClassifier(

    n_estimators=100,

    max_depth=3,

    learning_rate=0.05,

    objective="binary:logistic",

    eval_metric="logloss",

    random_state=42,

    n_jobs=-1
)


# ============================================================
# 15. TRAIN MODEL
# ============================================================

print("\nTraining XGBoost model...")

train_start = time.perf_counter()

model.fit(
    X_train_sel,
    y_train
)

train_end = time.perf_counter()

training_time = (
    train_end -
    train_start
)


# ============================================================
# 16. MODEL INFERENCE
# ============================================================

infer_start = time.perf_counter()

y_pred = model.predict(
    X_test_sel
)

y_probs = model.predict_proba(
    X_test_sel
)[:, 1]

infer_end = time.perf_counter()


inference_time = (
    infer_end -
    infer_start
)


per_sample_latency = (
    inference_time /
    len(X_test_sel)
) * 1000


# ============================================================
# 17. CALCULATE PERFORMANCE
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

logloss = log_loss(
    y_test,
    y_probs
)

roc_auc = roc_auc_score(
    y_test,
    y_probs
)


# ============================================================
# 18. DISPLAY RESULTS
# ============================================================

print("\n")
print("=" * 60)

print("XGBOOST PERFORMANCE")

print("=" * 60)


print(
    f"\nTraining Time: "
    f"{training_time:.4f} seconds"
)


print(
    f"Inference Time: "
    f"{inference_time:.4f} seconds"
)


print(
    f"Per-Sample Latency: "
    f"{per_sample_latency:.4f} ms/sample"
)


print(
    f"\nAccuracy Score: "
    f"{accuracy:.6f}"
)


print(
    f"Log Loss: "
    f"{logloss:.6f}"
)


print(
    f"ROC-AUC Score: "
    f"{roc_auc:.6f}"
)


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        zero_division=0
    )
)


print("Confusion Matrix:")

print(
    confusion_matrix(
        y_test,
        y_pred
    )
)


print("\nTest samples:")

print(
    len(y_test)
)


print("\nTest class distribution:")

print(
    y_test.value_counts()
)


# ============================================================
# 19. SAVE MODEL + PREPROCESSING INFORMATION
# ============================================================

print("\nSaving model...")


model_artifacts = {

    # Trained XGBoost model
    "model": model,

    # Original training feature names
    "train_columns": train_columns,

    # Median values used for missing data
    "medians": train_medians,

    # Variance threshold object
    "variance_selector": vt,

    # Features removed because of high correlation
    "high_corr_features": high_corr,

    # Final 15 features used by XGBoost
    "selected_features": top_features

}


joblib.dump(
    model_artifacts,
    model_path
)


# ============================================================
# 20. VERIFY SAVED MODEL
# ============================================================

if model_path.exists():

    file_size = (
        model_path.stat().st_size
        / (1024 * 1024)
    )

    print("\n")
    print("=" * 60)

    print(
        "MODEL SAVED SUCCESSFULLY"
    )

    print("=" * 60)

    print(
        f"\nLocation:\n"
        f"{model_path}"
    )

    print(
        f"\nFile size: "
        f"{file_size:.2f} MB"
    )

    print(
        "\nSaved information:"
    )

    print(
        "✓ XGBoost model"
    )

    print(
        "✓ Training columns"
    )

    print(
        "✓ Training medians"
    )

    print(
        "✓ Variance selector"
    )

    print(
        "✓ Correlation filtering"
    )

    print(
        "✓ Selected 15 features"
    )

else:

    raise RuntimeError(
        "Model file was not created."
    )


print("\n========================================")

print(
    "NIDS MODEL TRAINING COMPLETED"
)

print("========================================")