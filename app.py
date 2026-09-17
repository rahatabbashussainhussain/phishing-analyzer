"""
Web interface for the phishing analyzer.
Paste a URL or a block of email text and get a risk assessment.

Usage:
    python app.py
    Then open http://127.0.0.1:5000
"""

from flask import Flask, render_template, request

from phishing_checker import analyze_text, analyze_url

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    text_result = None
    submitted_input = ""

    if request.method == "POST":
        submitted_input = request.form.get("input_text", "").strip()
        mode = request.form.get("mode", "url")

        if submitted_input:
            if mode == "url":
                result = analyze_url(submitted_input)
            else:
                text_result = analyze_text(submitted_input)

    return render_template(
        "index.html",
        result=result,
        text_result=text_result,
        submitted_input=submitted_input,
    )


if __name__ == "__main__":
    app.run(debug=True)
