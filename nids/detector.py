import joblib
import pandas as pd
import numpy as np
from pathlib import Path


# ============================================================
# 1. FIND SAVED MODEL
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    BASE_DIR
    / "model"
    / "xgboost_nids_model.pkl"
)


# ============================================================
# 2. LOAD MODEL
# ============================================================

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Model not found at:\n{MODEL_PATH}\n\n"
        "Run model/xg.py first."
    )


artifacts = joblib.load(MODEL_PATH)

model = artifacts["model"]

train_columns = artifacts["train_columns"]

medians = artifacts["medians"]

variance_selector = artifacts["variance_selector"]

high_corr_features = artifacts["high_corr_features"]

selected_features = artifacts["selected_features"]


print("NIDS model loaded successfully.")

print("\nSelected features:")

for feature in selected_features:
    print("-", feature)


# ============================================================
# 3. PREPROCESS INPUT FEATURES
# ============================================================

def preprocess_features(feature_data):
    """
    Prepares new network-flow features in exactly the same
    way as the training data.
    """

    # Convert dictionary to DataFrame
    if isinstance(feature_data, dict):

        feature_data = pd.DataFrame(
            [feature_data]
        )

    elif isinstance(feature_data, pd.Series):

        feature_data = feature_data.to_frame().T

    elif not isinstance(
        feature_data,
        pd.DataFrame
    ):

        raise TypeError(
            "feature_data must be a dictionary, "
            "Series, or DataFrame."
        )


    # --------------------------------------------------------
    # Make a copy
    # --------------------------------------------------------

    df = feature_data.copy()


    # --------------------------------------------------------
    # Make sure all training columns exist
    # --------------------------------------------------------

    missing_columns = [
        column
        for column in train_columns
        if column not in df.columns
    ]


    if missing_columns:

        raise ValueError(
            "Missing required features:\n"
            + "\n".join(missing_columns)
        )


    # Keep only training columns
    df = df[train_columns]


    # --------------------------------------------------------
    # Convert everything to numeric
    # --------------------------------------------------------

    df = df.apply(
        pd.to_numeric,
        errors="coerce"
    )


    # --------------------------------------------------------
    # Replace infinity
    # --------------------------------------------------------

    df = df.replace(
        [np.inf, -np.inf],
        np.nan
    )


    # --------------------------------------------------------
    # Fill missing values using training medians
    # --------------------------------------------------------

    df = df.fillna(medians)


    # --------------------------------------------------------
    # Variance filtering
    # --------------------------------------------------------

    df_variance = variance_selector.transform(
        df
    )


    variance_features = [
        column
        for column, keep
        in zip(
            train_columns,
            variance_selector.get_support()
        )
        if keep
    ]


    df_variance = pd.DataFrame(
        df_variance,
        columns=variance_features
    )


    # --------------------------------------------------------
    # Remove high-correlation features
    # --------------------------------------------------------

    df_corr = df_variance.drop(
        columns=high_corr_features,
        errors="ignore"
    )


    # --------------------------------------------------------
    # Select final 15 features
    # --------------------------------------------------------

    missing_selected = [
        feature
        for feature in selected_features
        if feature not in df_corr.columns
    ]


    if missing_selected:

        raise ValueError(
            "Selected features missing after preprocessing:\n"
            + "\n".join(missing_selected)
        )


    df_final = df_corr[
        selected_features
    ]


    return df_final


# ============================================================
# 4. DETECTION FUNCTION
# ============================================================

def detect(feature_data):
    """
    Detects whether a network flow is Normal or an Attack.

    Returns:
        prediction
        confidence
        risk_score
        selected_features
    """

    # --------------------------------------------------------
    # Preprocess
    # --------------------------------------------------------

    processed_data = preprocess_features(
        feature_data
    )


    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    prediction = model.predict(
        processed_data
    )[0]


    # --------------------------------------------------------
    # Probability
    # --------------------------------------------------------

    probabilities = model.predict_proba(
        processed_data
    )[0]


    normal_probability = float(
        probabilities[0]
    )

    attack_probability = float(
        probabilities[1]
    )


    # --------------------------------------------------------
    # Convert prediction
    # --------------------------------------------------------

    if prediction == 1:

        result = "Attack"

        confidence = attack_probability

    else:

        result = "Normal"

        confidence = normal_probability


    # --------------------------------------------------------
    # Risk score
    #
    # Attack probability × 100
    # --------------------------------------------------------

    risk_score = attack_probability * 100


    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    if risk_score >= 80:

        severity = "High"

    elif risk_score >= 50:

        severity = "Medium"

    else:

        severity = "Low"


    # --------------------------------------------------------
    # Return result
    # --------------------------------------------------------

    return {

        "prediction": result,

        "prediction_value": int(prediction),

        "confidence": round(
            confidence * 100,
            2
        ),

        "attack_probability": round(
            attack_probability * 100,
            2
        ),

        "normal_probability": round(
            normal_probability * 100,
            2
        ),

        "risk_score": round(
            risk_score,
            2
        ),

        "severity": severity,

        "features": {
            feature: float(
                processed_data.iloc[0][feature]
            )
            for feature in selected_features
        }

    }


# ============================================================
# 5. TEST DETECTOR
# ============================================================

if __name__ == "__main__":

    print("\n")
    print("=" * 60)
    print("NIDS DETECTOR TEST")
    print("=" * 60)


    # --------------------------------------------------------
    # Load one row from the cleaned dataset
    # --------------------------------------------------------

    dataset_path = (
        BASE_DIR
        / "model"
        / "cleaned_dataset.csv"
    )


    if not dataset_path.exists():

        raise FileNotFoundError(
            "cleaned_dataset.csv not found."
        )


    test_df = pd.read_csv(
        dataset_path
    )


    # --------------------------------------------------------
    # Remove target
    # --------------------------------------------------------

    if "target" in test_df.columns:

        test_features = test_df.drop(
            columns=["target"]
        )

    else:

        test_features = test_df


    # --------------------------------------------------------
    # Test first row
    # --------------------------------------------------------

    test_row = test_features.iloc[0]


    # --------------------------------------------------------
    # Run detection
    # --------------------------------------------------------

    result = detect(
        test_row
    )


    # --------------------------------------------------------
    # Display result
    # --------------------------------------------------------

    print("\nDetection Result")
    print("-" * 40)

    print(
        "Prediction:",
        result["prediction"]
    )

    print(
        "Confidence:",
        f'{result["confidence"]}%'
    )

    print(
        "Attack Probability:",
        f'{result["attack_probability"]}%'
    )

    print(
        "Normal Probability:",
        f'{result["normal_probability"]}%'
    )

    print(
        "Risk Score:",
        result["risk_score"]
    )

    print(
        "Severity:",
        result["severity"]
    )

    print("\nFeatures used:")

    for feature, value in result[
        "features"
    ].items():

        print(
            f"{feature}: {value}"
        )


    print("\n")
    print("=" * 60)
    print("DETECTOR TEST COMPLETED")
    print("=" * 60)