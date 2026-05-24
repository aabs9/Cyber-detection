from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import sqlite3
import time
import json
from datetime import datetime
import os
app = Flask(__name__)
CORS(app)

API_KEY = "11476d364781a8275b04179e64e9b1191ef72a58464edb1e375d5bed913b6821"

FOLDER = r"C:\Users\SHAMAMA\PycharmProjects\pythonProject\pythonn"

def init_db():
    conn = sqlite3.connect("threats.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT,
            type        TEXT,
            malicious   INTEGER,
            suspicious  INTEGER,
            clean       INTEGER,
            total       INTEGER,
            verdict     TEXT,
            threat_type TEXT,
            engines     TEXT,
            scanned_at  TEXT
        )
    ''')
    conn.commit()
    conn.close()

def classify_threat(malicious, suspicious, engines_detail):
    if malicious == 0 and suspicious == 0:
        return "Clean"
    categories = []
    for name, result in engines_detail.items():
        cat = result.get("category", "").lower()
        res = (result.get("result") or "").lower()
        if "ransom" in res:
            categories.append("Ransomware")
        elif any(k in res for k in ["trojan", "troj"]):
            categories.append("Trojan")
        elif "phish" in res:
            categories.append("Phishing")
        elif any(k in res for k in ["spyware", "spy"]):
            categories.append("Spyware")
        elif any(k in res for k in ["adware", "ad"]):
            categories.append("Adware")
        elif any(k in res for k in ["malware", "virus", "worm"]):
            categories.append("Malware")
        elif cat == "malicious":
            categories.append("Malware")
    if not categories:
        return "Suspicious" if suspicious > 0 else "Malware"
    return max(set(categories), key=categories.count)

def save_scan(target, scan_type, malicious, suspicious, clean, total, verdict, threat_type, engines_str):
    conn = sqlite3.connect("threats.db")
    c = conn.cursor()
    c.execute('''
        INSERT INTO scans
        (target, type, malicious, suspicious, clean, total, verdict, threat_type, engines, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (target, scan_type, malicious, suspicious, clean, total,
          verdict, threat_type, engines_str,
          datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def scan_with_virustotal(target, scan_type):
    headers = {"x-apikey": API_KEY}

    if scan_type == "url":
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": target}
        )
        scan_id = response.json()["data"]["id"]
        time.sleep(15)
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
            headers=headers
        )
        attr           = result.json()["data"]["attributes"]
        stats          = attr["stats"]
        engines_detail = attr.get("results", {})

    elif scan_type == "ip":
        result = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{target}",
            headers=headers
        )
        attr           = result.json()["data"]["attributes"]
        stats          = attr["last_analysis_stats"]
        engines_detail = attr.get("last_analysis_results", {})

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    clean      = stats.get("undetected", 0)
    total      = sum(stats.values())
    verdict    = "MALICIOUS" if malicious > 10 else "SUSPICIOUS" if malicious > 0 else "CLEAN"
    threat_type = classify_threat(malicious, suspicious, engines_detail)

    top_engines = []
    for name, res in list(engines_detail.items())[:20]:
        cat         = res.get("category", "undetected")
        result_name = res.get("result") or "Clean"
        if cat in ["malicious", "suspicious"] or len(top_engines) < 8:
            top_engines.append({
                "name":   name,
                "verdict": result_name,
                "cat":    cat
            })
        if len(top_engines) >= 8:
            break

    engines_str = json.dumps(top_engines)
    save_scan(target, scan_type, malicious, suspicious, clean, total, verdict, threat_type, engines_str)

    return {
        "target":      target,
        "type":        scan_type,
        "malicious":   malicious,
        "suspicious":  suspicious,
        "clean":       clean,
        "total":       total,
        "verdict":     verdict,
        "threat_type": threat_type,
        "engines":     top_engines
    }
def scan_file_virustotal(file_path, file_name):
    headers = {"x-apikey": API_KEY}

    with open(file_path, "rb") as f:
        response = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files={"file": (file_name, f)}
        )

    if response.status_code != 200:
        return {"error": "فشل رفع الملف"}

    scan_id = response.json()["data"]["id"]
    time.sleep(20)

    result = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
        headers=headers
    )

    attr           = result.json()["data"]["attributes"]
    stats          = attr["stats"]
    engines_detail = attr.get("results", {})

    malicious   = stats.get("malicious", 0)
    suspicious  = stats.get("suspicious", 0)
    clean       = stats.get("undetected", 0)
    total       = sum(stats.values())
    verdict     = "MALICIOUS" if malicious > 10 else "SUSPICIOUS" if malicious > 0 else "CLEAN"
    threat_type = classify_threat(malicious, suspicious, engines_detail)

    top_engines = []
    for name, res in list(engines_detail.items())[:20]:
        cat         = res.get("category", "undetected")
        result_name = res.get("result") or "Clean"
        if cat in ["malicious", "suspicious"] or len(top_engines) < 8:
            top_engines.append({
                "name":    name,
                "verdict": result_name,
                "cat":     cat
            })
        if len(top_engines) >= 8:
            break

    engines_str = json.dumps(top_engines)
    save_scan(file_name, "file", malicious, suspicious, clean, total, verdict, threat_type, engines_str)

    return {
        "target":      file_name,
        "type":        "file",
        "malicious":   malicious,
        "suspicious":  suspicious,
        "clean":       clean,
        "total":       total,
        "verdict":     verdict,
        "threat_type": threat_type,
        "engines":     top_engines
    }
@app.route("/scan", methods=["POST"])
def scan():
    body      = request.json
    target    = body.get("target", "")
    scan_type = body.get("type", "url")
    if not target:
        return jsonify({"error": "أدخل رابطاً أو IP"}), 400
    result = scan_with_virustotal(target, scan_type)
    return jsonify(result)

@app.route("/scan-file", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "لم يتم رفع أي ملف"}), 400

    file      = request.files["file"]
    file_name = file.filename

    if file_name == "":
        return jsonify({"error": "اسم الملف فارغ"}), 400

    # حفظ الملف مؤقتاً
    temp_path = os.path.join(FOLDER, "temp_" + file_name)
    file.save(temp_path)

    try:
        result = scan_file_virustotal(temp_path, file_name)
    finally:
        # احذف الملف المؤقت بعد الفحص
        if os.path.exists(temp_path):
            os.remove(temp_path)

    return jsonify(result)

@app.route("/upload-page")
def serve_upload():
    return send_from_directory(FOLDER, "upload.html")

@app.route("/history")
def history():
    conn = sqlite3.connect("threats.db")
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()
    return jsonify([{
        "id":         r[0],
        "target":     r[1],
        "type":       r[2],
        "malicious":  r[3],
        "suspicious": r[4],
        "clean":      r[5],
        "total":      r[6],
        "verdict":    r[7],
        "threat_type": r[8],
        "scanned_at": r[10]
    } for r in rows])

@app.route("/stats")
def stats():
    conn = sqlite3.connect("threats.db")
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM scans")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scans WHERE verdict != 'CLEAN'")
    threats = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'CLEAN'")
    clean = c.fetchone()[0]
    c.execute("SELECT threat_type, COUNT(*) as cnt FROM scans GROUP BY threat_type ORDER BY cnt DESC")
    breakdown = [{"type": r[0], "count": r[1]} for r in c.fetchall()]
    conn.close()
    return jsonify({
        "total":     total,
        "threats":   threats,
        "clean":     clean,
        "breakdown": breakdown
    })

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route("/app")
def serve_index():
    return send_from_directory(FOLDER, "index.html")

@app.route("/history-page")
def serve_history():
    return send_from_directory(FOLDER, "history.html")
@app.route("/statistics-page")
def serve_statistics():
    return send_from_directory(FOLDER, "statistics.html")
init_db()

if __name__ == "__main__":
    app.run(debug=True, port=5000, host="127.0.0.1")
