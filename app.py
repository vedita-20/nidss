from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    redirect,
    url_for,
    session
)

from dotenv import load_dotenv

from nids.db import (
    db,
    User,
    Traffic,
    Alert,
    Explanation,
    DetectionRule
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

import os

from sqlalchemy import func


# ========================================
# LOAD ENVIRONMENT VARIABLES
# ========================================

load_dotenv()


# ========================================
# CREATE FLASK APP
# ========================================

app = Flask(__name__)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "nids-secret-key-2026"
)


# ========================================
# DATABASE CONFIGURATION
# ========================================

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
    "pool_size": 5,
    "max_overflow": 2
}

db.init_app(app)


# ========================================
# LOGIN REQUIRED HELPER
# ========================================

def login_required():
    return session.get("logged_in") is True


# ========================================
# LOGIN
# ========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if session.get("logged_in"):
        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        user = User.query.filter_by(
            username=username
        ).first()

        if user and check_password_hash(
            user.password_hash,
            password
        ):

            session.clear()

            session["logged_in"] = True
            session["user_id"] = user.id
            session["username"] = user.username
            session["user_name"] = user.name
            session["user_email"] = user.email

            return redirect(
                url_for("dashboard")
            )

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template(
        "login.html"
    )


# ========================================
# LOGOUT
# ========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ========================================
# SIGNUP
# ========================================

@app.route(
    "/signup",
    methods=["GET", "POST"]
)
def signup():

    if session.get("logged_in"):
        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # --------------------------------
        # VALIDATION
        # --------------------------------

        if (
            not name
            or not email
            or not username
            or not password
        ):

            return render_template(
                "signup.html",
                error="Please fill in all fields."
            )

        if password != confirm_password:

            return render_template(
                "signup.html",
                error="Passwords do not match."
            )

        if len(password) < 6:

            return render_template(
                "signup.html",
                error=(
                    "Password must contain "
                    "at least 6 characters."
                )
            )

        # --------------------------------
        # CHECK USERNAME
        # --------------------------------

        existing_username = User.query.filter_by(
            username=username
        ).first()

        if existing_username:

            return render_template(
                "signup.html",
                error="Username already exists."
            )

        # --------------------------------
        # CHECK EMAIL
        # --------------------------------

        existing_email = User.query.filter_by(
            email=email
        ).first()

        if existing_email:

            return render_template(
                "signup.html",
                error=(
                    "An account with this "
                    "email already exists."
                )
            )

        # --------------------------------
        # CREATE USER
        # --------------------------------

        password_hash = generate_password_hash(
            password
        )

        user = User(
            name=name,
            email=email,
            username=username,
            password_hash=password_hash
        )

        db.session.add(user)
        db.session.commit()

        return redirect(
            url_for("login")
        )

    return render_template(
        "signup.html"
    )


# ========================================
# FORGOT PASSWORD
# ========================================

@app.route(
    "/forgot-password",
    methods=["GET", "POST"]
)
def forgot_password():

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        user = User.query.filter_by(
            email=email
        ).first()

        if not user:

            return render_template(
                "forgot_password.html",
                error=(
                    "No account found with "
                    "this email."
                )
            )

        session["reset_user_id"] = user.id

        return redirect(
            url_for("reset_password")
        )

    return render_template(
        "forgot_password.html"
    )


# ========================================
# RESET PASSWORD
# ========================================

@app.route(
    "/reset-password",
    methods=["GET", "POST"]
)
def reset_password():

    user_id = session.get(
        "reset_user_id"
    )

    if not user_id:

        return redirect(
            url_for("forgot_password")
        )

    user = db.session.get(
        User,
        user_id
    )

    if not user:

        session.pop(
            "reset_user_id",
            None
        )

        return redirect(
            url_for("forgot_password")
        )

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if len(password) < 6:

            return render_template(
                "reset_password.html",
                error=(
                    "Password must contain "
                    "at least 6 characters."
                )
            )

        if password != confirm_password:

            return render_template(
                "reset_password.html",
                error="Passwords do not match."
            )

        user.password_hash = (
            generate_password_hash(password)
        )

        db.session.commit()

        session.pop(
            "reset_user_id",
            None
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "reset_password.html"
    )


# ========================================
# PROFILE
# ========================================

@app.route("/profile")
def profile():

    if not login_required():

        return redirect(
            url_for("login")
        )

    user = db.session.get(
        User,
        session.get("user_id")
    )

    if not user:

        session.clear()

        return redirect(
            url_for("login")
        )

    return render_template(
        "profile.html",
        user=user
    )


# ========================================
# HOME / DASHBOARD
# ========================================

@app.route("/")
def dashboard():

    if not login_required():

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html"
    )


# ========================================
# PAGE ROUTES
# ========================================

@app.route("/alerts")
def alerts():

    if not login_required():

        return redirect(
            url_for("login")
        )

    return render_template(
        "alerts.html"
    )


@app.route("/traffic")
def traffic():

    if not login_required():

        return redirect(
            url_for("login")
        )

    return render_template(
        "traffic.html"
    )


@app.route("/logs")
def logs():

    if not login_required():

        return redirect(
            url_for("login")
        )

    return render_template(
        "logs.html"
    )


@app.route("/analysis")
def analysis():

    if not login_required():

        return redirect(
            url_for("login")
        )

    return render_template(
        "analysis.html"
    )


@app.route("/reports")
def reports():

    if not login_required():

        return redirect(
            url_for("login")
        )

    return render_template(
        "reports.html"
    )


# ========================================
# DASHBOARD STATISTICS API
# ========================================

@app.route("/api/dashboard")
def api_dashboard():

    if not login_required():

        return jsonify({
            "error": "Authentication required"
        }), 401

    total_traffic = Traffic.query.count()

    total_attacks = Alert.query.count()

    active_alerts = Alert.query.filter_by(
        status="Unresolved"
    ).count()

    normal_traffic = (
        total_traffic -
        total_attacks
    )

    if total_traffic > 0:

        attack_percentage = (
            total_attacks /
            total_traffic
        ) * 100

    else:

        attack_percentage = 0

    latest_traffic = Traffic.query.order_by(
        Traffic.timestamp.desc()
    ).first()

    latest_attack = Alert.query.order_by(
        Alert.timestamp.desc()
    ).first()

    return jsonify({

        "total_traffic":
            total_traffic,

        "total_attacks":
            total_attacks,

        "active_alerts":
            active_alerts,

        "normal_traffic":
            normal_traffic,

        "attack_percentage":
            round(
                attack_percentage,
                2
            ),

        "latest_traffic": (
            latest_traffic.timestamp
            if latest_traffic
            else None
        ),

        "latest_attack": (
            latest_attack.timestamp
            if latest_attack
            else None
        )
    })


# ========================================
# DASHBOARD TRENDS API
# ========================================

@app.route("/api/dashboard/trends")
def dashboard_trends():

    if not login_required():

        return jsonify({
            "error": "Authentication required"
        }), 401

    traffic_records = Traffic.query.order_by(
        Traffic.timestamp.asc()
    ).limit(20).all()

    alert_records = Alert.query.order_by(
        Alert.timestamp.asc()
    ).limit(20).all()

    traffic_trend = []

    for index, traffic_record in enumerate(
        traffic_records,
        start=1
    ):

        traffic_trend.append(index)

    attack_trend = []

    for index, alert in enumerate(
        alert_records,
        start=1
    ):

        attack_trend.append(index)

    if not traffic_trend:
        traffic_trend = [0]

    if not attack_trend:
        attack_trend = [0]

    while len(attack_trend) < len(traffic_trend):

        attack_trend.append(
            attack_trend[-1]
        )

    attack_rate = []

    for traffic_count, attack_count in zip(
        traffic_trend,
        attack_trend
    ):

        if traffic_count > 0:

            rate = (
                attack_count /
                traffic_count
            ) * 100

        else:

            rate = 0

        attack_rate.append(
            round(
                rate,
                2
            )
        )

    active_alerts = Alert.query.filter_by(
        status="Unresolved"
    ).count()

    active_alert_trend = [
        active_alerts
        for _ in traffic_trend
    ]

    return jsonify({

        "traffic":
            traffic_trend,

        "attacks":
            attack_trend,

        "active_alerts":
            active_alert_trend,

        "attack_rate":
            attack_rate
    })


# ========================================
# RESOLVE ALERT API
# ========================================

@app.route(
    "/api/alerts/<int:alert_id>/resolve",
    methods=["PUT"]
)
def resolve_alert(alert_id):

    if not login_required():

        return jsonify({
            "error": "Authentication required"
        }), 401

    alert = db.session.get(
        Alert,
        alert_id
    )

    if not alert:

        return jsonify({
            "error":
                "Alert not found"
        }), 404

    alert.status = "Resolved"

    db.session.commit()

    return jsonify({

        "message":
            "Alert resolved successfully",

        "alert_id":
            alert.id,

        "status":
            alert.status
    })


# ========================================
# SHAP EXPLANATION API
# ========================================

@app.route(
    "/api/explanations/<int:alert_id>"
)
def api_explanations(alert_id):

    # --------------------------------
    # AUTHENTICATION
    # --------------------------------

    if not login_required():

        return jsonify({
            "error": "Authentication required"
        }), 401

    # --------------------------------
    # FIND ALERT
    # --------------------------------

    alert = db.session.get(
        Alert,
        alert_id
    )

    if not alert:

        return jsonify({
            "error": "Alert not found"
        }), 404

    # --------------------------------
    # GET SAVED SHAP EXPLANATIONS
    # --------------------------------

    explanations = Explanation.query.filter_by(
        alert_id=alert_id
    ).order_by(
        func.abs(
            Explanation.shap_value
        ).desc()
    ).all()

    # --------------------------------
    # NO EXPLANATIONS FOUND
    # --------------------------------

    if not explanations:

        return jsonify({
            "error": (
                "No SHAP explanations "
                "found for this alert."
            ),
            "alert_id": alert_id,
            "explanations": []
        }), 404

    # --------------------------------
    # CONVERT TO JSON
    # --------------------------------

    data = []

    for explanation in explanations:

        data.append({

            "feature_name":
                explanation.feature_name,

            "feature_value":
                explanation.feature_value,

            "shap_value":
                explanation.shap_value,

            "contribution":
                explanation.contribution
        })

    return jsonify(data)


# ========================================
# RECENT TRAFFIC API
# ========================================

@app.route("/api/traffic")
def api_traffic():

    if not login_required():

        return jsonify({
            "error": "Authentication required"
        }), 401

    records = Traffic.query.order_by(
        Traffic.timestamp.desc()
    ).limit(20).all()

    data = []

    for row in records:

        data.append({

            "id":
                row.id,

            "timestamp":
                row.timestamp,

            "source_ip":
                row.source_ip,

            "destination_ip":
                row.destination_ip,

            "source_port":
                row.source_port,

            "destination_port":
                row.destination_port,

            "protocol":
                row.protocol,

            "packet_count":
                row.packet_count,

            "flow_duration":
                row.flow_duration or 0,

            "total_bytes":
                row.total_bytes or 0
        })

    return jsonify(data)


# ========================================
# RECENT ALERTS API
# ========================================

@app.route("/api/alerts")
def api_alerts():

    if not login_required():

        return jsonify({
            "error": "Authentication required"
        }), 401

    records = Alert.query.order_by(
        Alert.timestamp.desc()
    ).limit(20).all()

    data = []

    for row in records:

        data.append({

            "id":
                row.id,

            "timestamp":
                row.timestamp,

            "source_ip":
                row.source_ip,

            "destination_ip":
                row.destination_ip,

            "source_port":
                row.source_port,

            "destination_port":
                row.destination_port,

            "protocol":
                row.protocol,

            "attack_type":
                row.attack_type,

            "confidence":
                row.confidence,

            "risk_score":
                row.risk_score,

            "severity":
                row.severity,

            "status":
                row.status
        })

    return jsonify(data)


# ========================================
# NETWORK LOGS API
# ========================================

@app.route("/api/logs")
def api_logs():

    if not login_required():

        return jsonify({
            "error": "Authentication required"
        }), 401

    traffic_records = Traffic.query.order_by(
        Traffic.timestamp.desc()
    ).limit(50).all()

    alert_records = Alert.query.order_by(
        Alert.timestamp.desc()
    ).all()

    alert_map = {}

    for alert in alert_records:

        key = (
            alert.source_ip,
            alert.destination_ip,
            alert.source_port,
            alert.destination_port
        )

        alert_map[key] = {

            "attack_type":
                alert.attack_type,

            "confidence":
                alert.confidence,

            "risk_score":
                alert.risk_score,

            "severity":
                alert.severity,

            "status":
                alert.status
        }

    data = []

    for row in traffic_records:

        key = (
            row.source_ip,
            row.destination_ip,
            row.source_port,
            row.destination_port
        )

        alert_info = alert_map.get(key)

        if alert_info:

            result = "Attack"

            attack_type = (
                alert_info["attack_type"]
            )

            confidence = (
                alert_info["confidence"]
            )

            risk_score = (
                alert_info["risk_score"]
            )

            severity = (
                alert_info["severity"]
            )

            status = (
                alert_info["status"]
            )

        else:

            result = "Normal"

            attack_type = "-"

            confidence = 0

            risk_score = 0

            severity = "Low"

            status = "Normal"

        data.append({

            "id":
                row.id,

            "timestamp":
                row.timestamp,

            "source_ip":
                row.source_ip,

            "destination_ip":
                row.destination_ip,

            "source_port":
                row.source_port,

            "destination_port":
                row.destination_port,

            "protocol":
                row.protocol,

            "packet_count":
                row.packet_count,

            "flow_duration":
                row.flow_duration or 0,

            "total_bytes":
                row.total_bytes or 0,

            "result":
                result,

            "attack_type":
                attack_type,

            "confidence":
                confidence,

            "risk_score":
                risk_score,

            "severity":
                severity,

            "status":
                status
        })

    return jsonify(data)


# ========================================
# ANALYSIS API
# ========================================

@app.route("/api/analysis")
def api_analysis():

    if not login_required():

        return jsonify({
            "error": "Authentication required"
        }), 401

    total_traffic = Traffic.query.count()

    total_attacks = Alert.query.count()

    normal_traffic = (
        total_traffic -
        total_attacks
    )

    if total_traffic > 0:

        attack_percentage = (
            total_attacks /
            total_traffic
        ) * 100

    else:

        attack_percentage = 0

    high = Alert.query.filter_by(
        severity="High"
    ).count()

    medium = Alert.query.filter_by(
        severity="Medium"
    ).count()

    low = Alert.query.filter_by(
        severity="Low"
    ).count()

    protocol_rows = db.session.query(
        Traffic.protocol,
        func.count(Traffic.id)
    ).group_by(
        Traffic.protocol
    ).all()

    protocols = {}

    for protocol, count in protocol_rows:

        protocol_name = str(protocol)

        if protocol_name == "6":
            protocol_name = "TCP"

        elif protocol_name == "17":
            protocol_name = "UDP"

        elif protocol_name == "1":
            protocol_name = "ICMP"

        protocols[protocol_name] = count

    source_rows = db.session.query(
        Alert.source_ip,
        func.count(Alert.id)
    ).group_by(
        Alert.source_ip
    ).order_by(
        func.count(Alert.id).desc()
    ).limit(10).all()

    top_sources = []

    for ip, count in source_rows:

        top_sources.append({

            "ip":
                ip,

            "count":
                count
        })

    port_rows = db.session.query(
        Alert.destination_port,
        func.count(Alert.id)
    ).group_by(
        Alert.destination_port
    ).order_by(
        func.count(Alert.id).desc()
    ).limit(10).all()

    top_ports = []

    for port, count in port_rows:

        top_ports.append({

            "port":
                port,

            "count":
                count
        })

    attack_type_rows = db.session.query(
        Alert.attack_type,
        func.count(Alert.id)
    ).group_by(
        Alert.attack_type
    ).order_by(
        func.count(Alert.id).desc()
    ).all()

    attack_types = []

    for attack_type, count in attack_type_rows:

        attack_types.append({

            "type":
                attack_type,

            "count":
                count
        })

    recent_alerts = Alert.query.order_by(
        Alert.timestamp.desc()
    ).limit(10).all()

    recent_attacks = []

    for alert in recent_alerts:

        recent_attacks.append({

            "timestamp":
                alert.timestamp,

            "source_ip":
                alert.source_ip,

            "destination_ip":
                alert.destination_ip,

            "attack_type":
                alert.attack_type,

            "confidence":
                alert.confidence,

            "risk_score":
                alert.risk_score,

            "severity":
                alert.severity,

            "status":
                alert.status
        })

    return jsonify({

        "summary": {

            "total_traffic":
                total_traffic,

            "total_attacks":
                total_attacks,

            "normal_traffic":
                normal_traffic,

            "attack_percentage":
                round(
                    attack_percentage,
                    2
                )
        },

        "severity": {

            "high":
                high,

            "medium":
                medium,

            "low":
                low
        },

        "protocols":
            protocols,

        "top_sources":
            top_sources,

        "top_ports":
            top_ports,

        "attack_types":
            attack_types,

        "recent_attacks":
            recent_attacks
    })


# ========================================
# REPORTS API
# ========================================

@app.route("/api/reports")
def api_reports():

    if not login_required():

        return jsonify({
            "error": "Authentication required"
        }), 401

    total_traffic = Traffic.query.count()

    total_attacks = Alert.query.count()

    normal_traffic = (
        total_traffic -
        total_attacks
    )

    if total_traffic > 0:

        attack_percentage = (
            total_attacks /
            total_traffic
        ) * 100

    else:

        attack_percentage = 0

    high = Alert.query.filter_by(
        severity="High"
    ).count()

    medium = Alert.query.filter_by(
        severity="Medium"
    ).count()

    low = Alert.query.filter_by(
        severity="Low"
    ).count()

    protocol_rows = db.session.query(
        Traffic.protocol,
        func.count(Traffic.id)
    ).group_by(
        Traffic.protocol
    ).all()

    protocols = {}

    for protocol, count in protocol_rows:

        protocol_name = str(protocol)

        if protocol_name == "6":
            protocol_name = "TCP"

        elif protocol_name == "17":
            protocol_name = "UDP"

        elif protocol_name == "1":
            protocol_name = "ICMP"

        protocols[protocol_name] = count

    source_rows = db.session.query(
        Alert.source_ip,
        func.count(Alert.id)
    ).group_by(
        Alert.source_ip
    ).order_by(
        func.count(Alert.id).desc()
    ).limit(5).all()

    top_sources = []

    for ip, count in source_rows:

        top_sources.append({

            "ip":
                ip,

            "count":
                count
        })

    port_rows = db.session.query(
        Alert.destination_port,
        func.count(Alert.id)
    ).group_by(
        Alert.destination_port
    ).order_by(
        func.count(Alert.id).desc()
    ).limit(5).all()

    top_ports = []

    for port, count in port_rows:

        top_ports.append({

            "port":
                port,

            "count":
                count
        })

    recent_alerts = Alert.query.order_by(
        Alert.timestamp.desc()
    ).limit(20).all()

    recent_attacks = []

    for alert in recent_alerts:

        recent_attacks.append({

            "id":
                alert.id,

            "timestamp": (

                alert.timestamp.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                if alert.timestamp

                else "-"
            ),

            "source_ip":
                alert.source_ip or "-",

            "destination_ip": (

                alert.destination_ip
                or "-"
            ),

            "source_port": (

                alert.source_port
                if alert.source_port is not None
                else "-"
            ),

            "destination_port": (

                alert.destination_port
                if alert.destination_port is not None
                else "-"
            ),

            "protocol":
                alert.protocol or "-",

            "attack_type": (

                alert.attack_type
                or "-"
            ),

            "confidence": (

                round(
                    alert.confidence,
                    2
                )

                if alert.confidence is not None
                else 0
            ),

            "risk_score": (

                round(
                    alert.risk_score,
                    2
                )

                if alert.risk_score is not None
                else 0
            ),

            "severity":
                alert.severity or "-",

            "status":
                alert.status or "-"
        })

    return jsonify({

        "summary": {

            "total_traffic":
                total_traffic,

            "total_attacks":
                total_attacks,

            "normal_traffic":
                normal_traffic,

            "attack_percentage":
                round(
                    attack_percentage,
                    2
                )
        },

        "severity": {

            "high":
                high,

            "medium":
                medium,

            "low":
                low
        },

        "protocols":
            protocols,

        "top_sources":
            top_sources,

        "top_ports":
            top_ports,

        "recent_attacks":
            recent_attacks
    })


# ========================================
# CREATE DATABASE TABLES
# ========================================

with app.app_context():

    db.create_all()


# ========================================
# RUN FLASK APPLICATION
# ========================================

if __name__ == "__main__":

    app.run(
        debug=True
    )

