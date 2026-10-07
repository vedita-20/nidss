from app import app

from nids.db import (
    db,
    Traffic,
    Alert,
    Explanation
)

from nids.explainable_ai import explain_prediction


def save_detection(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol,
    packet_count,
    flow_duration,
    total_bytes,
    result
):
    # Flask application context stays active
    # for the entire database operation.
    with app.app_context():

        try:

            # --------------------------------
            # SAVE TRAFFIC
            # --------------------------------

            traffic = Traffic(
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=str(protocol),
                packet_count=packet_count,
                flow_duration=flow_duration,
                total_bytes=total_bytes
            )

            db.session.add(traffic)

            # --------------------------------
            # SAVE ATTACK ALERT
            # --------------------------------

            if result["prediction"] == "Attack":

                alert = Alert(
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    source_port=source_port,
                    destination_port=destination_port,
                    protocol=str(protocol),
                    attack_type="Attack",
                    confidence=result["confidence"],
                    risk_score=result["risk_score"],
                    severity=result["severity"],
                    status="Unresolved"
                )

                db.session.add(alert)

                # Generate the Alert ID
                db.session.flush()

                print("\n[ALERT] Attack detected.")
                print(f"[ALERT] Alert ID: {alert.id}")

                # --------------------------------
                # GENERATE SHAP
                # --------------------------------

                print("\n[SHAP] Generating explanation...")

                explanations = explain_prediction(
                    result["features"]
                )

                print(
                    f"[SHAP] Generated "
                    f"{len(explanations)} explanations."
                )

                # --------------------------------
                # SAVE SHAP EXPLANATIONS
                # --------------------------------

                for item in explanations:

                    explanation = Explanation(
                        alert_id=alert.id,
                        feature_name=item["feature_name"],
                        feature_value=item["feature_value"],
                        shap_value=item["shap_value"],
                        contribution=item["contribution"]
                    )

                    db.session.add(explanation)

                # --------------------------------
                # SHOW TOP 5 SHAP FEATURES
                # --------------------------------

                print("\n[SHAP] Top contributing features:")

                for item in explanations[:5]:

                    print(
                        f"{item['feature_name']} : "
                        f"{item['shap_value']:.4f} "
                        f"({item['contribution']})"
                    )

            # --------------------------------
            # COMMIT
            # --------------------------------

            db.session.commit()

            print(
                "\n[DATABASE] Detection + SHAP "
                "saved to Neon PostgreSQL."
            )

        except Exception as e:

            # IMPORTANT:
            # Rollback happens INSIDE app context.
            db.session.rollback()

            print(
                f"\n[DATABASE ERROR] "
                f"Could not save detection: {e}"
            )

            print(
                f"[ERROR TYPE] {type(e).__name__}"
            )