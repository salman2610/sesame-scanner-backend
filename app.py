from flask import Flask, request, jsonify
import subprocess
import json

app = Flask(__name__)

# Import your scanner logic
from scanner import run_scan  # Make sure scanner.py has a function run_scan(url)

@app.route("/")
def home():
    return {"message": "Sesame Scanner Backend Running"}

@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            return jsonify({"error": "URL is required"}), 400

        # Run the scan
        results = run_scan(url)

        # Show only 3-4 issues
        limited_results = results[:4]

        # Add "contact sesame" message
        if len(results) > 4:
            limited_results.append(
                {"note": "Contact Sesame for full assessment."}
            )

        return jsonify({"issues": limited_results})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
