# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner import run_scan

app = Flask(__name__)
# For initial testing allow all origins. In prod, set origins to your GH pages domain.
CORS(app, resources={r"/scan": {"origins": "*"}})

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Sesame Scanner Backend Running"})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True})

@app.route("/scan", methods=["POST"])
def scan_endpoint():
    try:
        data = request.get_json(silent=True) or {}
        url = data.get("url", "").strip()
        if not url:
            return jsonify({"error":"No URL provided"}), 400

        full_findings = run_scan(url)  # list of dicts
        # Build preview: first 4 findings
        preview = full_findings[:4]
        locked = max(0, len(full_findings) - len(preview))

        return jsonify({
            "target": url,
            "runtime_seconds": None,
            "issues_preview": preview,
            "locked_count": locked,
            "note": "Contact Sesame for full assessment."
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
