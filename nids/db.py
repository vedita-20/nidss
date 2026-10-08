from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


# =========================
# USER MODEL
# =========================
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False
    )

    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# =========================
# TRAFFIC MODEL
# =========================
class Traffic(db.Model):
    __tablename__ = "traffic"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    source_ip = db.Column(db.String(45))
    destination_ip = db.Column(db.String(45))
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    packet_count = db.Column(db.Integer)
    flow_duration = db.Column(db.Float)
    total_bytes = db.Column(db.Integer)

# =========================
# ALERT MODEL
# =========================
class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=True
    )

    source_ip = db.Column(db.String(45))
    destination_ip = db.Column(db.String(45))
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    attack_type = db.Column(db.String(100))
    confidence = db.Column(db.Float)
    risk_score = db.Column(db.Float)
    severity = db.Column(db.String(20))
    status = db.Column(db.String(30), default="Unresolved")

# =========================
# SHAP EXPLANATION MODEL
# =========================
class Explanation(db.Model):
    __tablename__ = "explanations"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    alert_id = db.Column(
        db.Integer,
        db.ForeignKey("alerts.id"),
        nullable=False
    )

    feature_name = db.Column(
        db.String(100)
    )

    feature_value = db.Column(
        db.Float
    )

    shap_value = db.Column(
        db.Float
    )

    contribution = db.Column(
        db.String(20)
    )


# =========================
# DETECTION RULE MODEL
# =========================
class DetectionRule(db.Model):
    __tablename__ = "detection_rules"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(100),
        nullable=False
    )

    condition_type = db.Column(
        db.String(50),
        nullable=False
    )

    threshold = db.Column(
        db.Float,
        nullable=False
    )

    severity = db.Column(
        db.String(20),
        nullable=False
    )

    description = db.Column(
        db.String(255)
    )

    enabled = db.Column(
        db.Boolean,
        default=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )