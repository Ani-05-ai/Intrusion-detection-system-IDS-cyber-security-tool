from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for
from detection.aggregator import detect_event
from db import alerts_collection, users_collection
from bson.objectid import ObjectId
from agent.investigator import investigate_alert
from functools import wraps
import bcrypt

bp = Blueprint("detection", __name__)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("detection.login_page"))
        return f(*args, **kwargs)
    return wrapper


@bp.route("/", methods=["GET"])
def home():
    if "username" in session:
        return redirect(url_for("detection.dashboard"))
    return render_template("index.html")


@bp.route("/analyze", methods=["POST"])
def analyze():
    event = request.get_json()

    if event is None:
        return jsonify({"error": "No JSON body received"}), 400

    result = detect_event(event)
    alerts_collection.insert_one(result.copy())

    return jsonify(result)


@bp.route("/alerts", methods=["GET"])
def get_alerts():
    alerts = list(alerts_collection.find())
    for a in alerts:
        a["_id"] = str(a["_id"])
    return jsonify(alerts)


@bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    data = request.get_json()

    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "username and password required"}), 400

    username = data["username"]
    password = data["password"]

    if users_collection.find_one({"username": username}):
        return jsonify({"error": "username already exists"}), 409

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    users_collection.insert_one({
        "username": username,
        "password": hashed_pw
    })

    return jsonify({"message": "user created"}), 201


@bp.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        return render_template("login.html")

    data = request.get_json()

    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "username and password required"}), 400

    username = data["username"]
    password = data["password"]

    user = users_collection.find_one({"username": username})

    if not user:
        return jsonify({"error": "invalid username or password"}), 401

    if not bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        return jsonify({"error": "invalid username or password"}), 401

    session["username"] = username
    return jsonify({"message": "login successful"}), 200


@bp.route("/logout", methods=["GET"])
def logout():
    session.pop("username", None)
    return redirect(url_for("detection.login_page"))


@bp.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    return render_template("dashboard.html")


@bp.route("/investigate/<alert_id>", methods=["GET"])
def investigate(alert_id):
    alert = alerts_collection.find_one({"_id": ObjectId(alert_id)})

    if not alert:
        return jsonify({"error": "alert not found"}), 404

    source_ip = alert.get("event", {}).get("source_ip")
    query = {"_id": {"$ne": alert["_id"]}}
    if source_ip:
        query["event.source_ip"] = source_ip

    related = list(alerts_collection.find(query).limit(5))
    summary = investigate_alert(alert, related)

    return jsonify({
        "alert_id": str(alert["_id"]),
        "investigation": summary
    })

from rules.rules import run_rules

EXCLUDED_PATHS = ("/dashboard", "/alerts", "/analyze", "/investigate", "/login", "/signup", "/logout", "/static")

from flask import current_app

@bp.record_once
def register_global_hook(state):
    @state.app.before_request
    def monitor_live_traffic():
        if request.path.startswith(EXCLUDED_PATHS):
            return

        event = {
            "log_source": "web_server",
            "method": request.method,
            "url": request.full_path,
            "source_ip": request.remote_addr,
        }

        rule_results = run_rules(event)

        if rule_results:
            severity = max(
                [r["severity"] for r in rule_results],
                key=lambda x: {"low": 1, "medium": 2, "high": 3}[x]
            )
            alerts_collection.insert_one({
                "detected": True,
                "severity": severity,
                "source": "RULE",
                "rules": rule_results,
                "ml": None,
                "event": event
            })
