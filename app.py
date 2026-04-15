"""SecureDeploy demo API — minimal Flask app for pipeline testing."""
from flask import Flask, jsonify
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

APP_VERSION = os.getenv("APP_VERSION", "1.0.0")


@app.route("/health", methods=["GET"])
def health():
    """Kubernetes liveness probe target."""
    return jsonify({"status": "healthy", "version": APP_VERSION}), 200


@app.route("/ready", methods=["GET"])
def ready():
    """Kubernetes readiness probe target."""
    return jsonify({"ready": True}), 200


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "securedeploy-demo",
        "message": "DevSecOps guardrails active",
        "version": APP_VERSION
    }), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))
    logger.info(f"Starting SecureDeploy demo on port {port}")
    app.run(host="0.0.0.0", port=port)
