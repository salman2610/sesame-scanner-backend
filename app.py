# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner import scan


app = Flask(__name__)
# For production, set CORS to your GitHub Pages origin only
CORS(app, resources={r"/scan": {"origins": "*"}})


@app.route("/health", methods=["GET"]) # simple health check
def health():
return {"ok": True}


@app.route("/scan", methods=["POST"]) # expects JSON {url: "https://..."}
def scan_url():
data = request.get_json(silent=True) or {}
url = data.get("url", "").strip()
if not url:
return jsonify({"error": "No URL provided"}), 400


result = scan(url)
return jsonify(result)


if __name__ == "__main__":
# Local dev only
app.run(host="0.0.0.0", port=5000, debug=True)
