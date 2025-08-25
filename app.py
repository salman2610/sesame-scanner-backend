from flask import Flask, request, jsonify
from flask_cors import CORS
from scanner import run_scan

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend to call backend

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Sesame Scanner Backend Running"})

@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json()
        target_url = data.get("url")

        if not target_url:
            return jsonify({"error": "No URL provided"}), 400

        results = run_scan(target_url)
        return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
