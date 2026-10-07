import shap
import pandas as pd
import numpy as np

from detector import model, selected_features


# ============================================================
# SHAP EXPLAINER
# ============================================================

explainer = shap.TreeExplainer(model)


def explain_prediction(features):
    """
    Generate SHAP explanation for one NIDS prediction.

    Parameters:
        features: dictionary containing the selected NIDS features

    Returns:
        List of feature explanations
    """

    # --------------------------------------------------------
    # Create DataFrame in exact feature order
    # --------------------------------------------------------

    input_data = pd.DataFrame(
        [[features[feature] for feature in selected_features]],
        columns=selected_features
    )

    # --------------------------------------------------------
    # Calculate SHAP values
    # --------------------------------------------------------

    shap_values = explainer.shap_values(input_data)

    # --------------------------------------------------------
    # Handle different SHAP output formats
    # --------------------------------------------------------

    if isinstance(shap_values, list):
        shap_values = shap_values[1]

    shap_values = np.asarray(shap_values)

    if shap_values.ndim == 2:
        shap_values = shap_values[0]

    # --------------------------------------------------------
    # Create explanation list
    # --------------------------------------------------------

    explanations = []

    for feature, value, shap_value in zip(
        selected_features,
        input_data.iloc[0].values,
        shap_values
    ):

        if shap_value > 0:
            contribution = "Attack"
        else:
            contribution = "Normal"

        explanations.append({
            "feature_name": feature,
            "feature_value": float(value),
            "shap_value": float(shap_value),
            "contribution": contribution
        })

    # --------------------------------------------------------
    # Sort by absolute SHAP importance
    # --------------------------------------------------------

    explanations.sort(
        key=lambda x: abs(x["shap_value"]),
        reverse=True
    )

    return explanations