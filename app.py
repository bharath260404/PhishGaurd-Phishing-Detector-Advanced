
import joblib, pandas, sys, os
sys.path.insert(0, ".")
from java_heuristic import java_check
from flask import Flask, render_template_string, request
model = joblib.load("model_simple.pkl")
FEATURES = ["UrlLength", "AtSymbol", "IpAddress", "NoHttps"]
app = Flask(__name__)
HTML = open("template.html", "r", encoding="utf-8").read()

def extract_features(url):
    url_length = len(url)
    at_symbol = 1 if "@" in url else 0
    try:
        domain = url.split("/")[2]
        ip_address = 1 if all(part.isdigit() for part in domain.split(".") if part) else 0
    except Exception:
        ip_address = 0
    no_https = 0 if url.lower().startswith("https") else 1
    return {"UrlLength": url_length, "AtSymbol": at_symbol, "IpAddress": ip_address, "NoHttps": no_https}

@app.route("/", methods=["GET", "POST"])
def index():
    result = None; url = ""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            feats = extract_features(url)
            X = pandas.DataFrame([feats], columns=FEATURES)
            pred = int(model.predict(X)[0])
            prob = float(model.predict_proba(X)[:, 1][0])
            java_res = java_check(url)
            result = {"ml": {"pred": pred, "verdict": "PHISHING" if pred == 1 else "SAFE", "prob": f"{prob:.2%}", "prob_num": round(prob * 100), "features": feats}, "java": java_res}
    return render_template_string(HTML, result=result, url=url)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
