import os, time, json, logging, hashlib, sqlite3, configparser, requests, psutil, shutil
from datetime import datetime, timezone, timedelta

# ── CONFIG ──
SCAN_INTERVAL       = 1
STATE_FILE          = "monitor_state.ini"
THREAT_FILE         = "threats.json"
LOG_FILE            = "data/threat_log.txt"
ALERT_DB            = "data/threats.db"
QUARANTINE_FOLDER   = "quarantine/"
TELEGRAM_TOKEN      = "Your telegram token here"
TELEGRAM_CHAT_ID    =  "Your chat id"
IST                 = timezone(timedelta(hours=5, minutes=30))

# ── INIT ──
os.makedirs("data", exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

conn = sqlite3.connect(ALERT_DB, check_same_thread=False)
cursor = conn.cursor()
cursor.execute("""CREATE TABLE IF NOT EXISTS alerts (
    timestamp TEXT, process_name TEXT, pid TEXT, username TEXT,
    exe TEXT, reason TEXT, quarantined TEXT
)""")
conn.commit()

# ── TELEGRAM ──
def send_telegram(msg):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": msg})
    except Exception as e:
        logging.error(f"[TELEGRAM ERROR] {e}")

# ── QUARANTINE ──
def quarantine(exe, pid):
    try:
        dst = os.path.join(QUARANTINE_FOLDER, f"{os.path.basename(exe)}_{int(time.time())}")
        with open(exe, "rb") as f: hashval = hashlib.sha256(f.read()).hexdigest()
        shutil.copy2(exe, dst)
        os.kill(pid, 9)
        return "Yes"
    except Exception as e:
        logging.error(f"[QUARANTINE ERROR] {e}")
        return "No"

# ── ALERT LOGGING ──
def log_alert(proc, reason, status):
    ts   = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
    name = proc.info.get("name", "Unknown")
    pid  = str(proc.info.get("pid", ""))
    user = proc.info.get("username", "Unknown")
    exe  = proc.info.get("exe", "N/A")

    cursor.execute("INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)", (
        ts, name, pid, user, exe, reason, status
    ))
    conn.commit()

    label = "🛡️ Quarantined" if status == "Yes" else "🔔 Alert-Only"
    msg = (
        f"🚨 Threat Detected\n"
        f"📎 {name} (PID {pid})\n"
        f"📋 {reason}\n"
        f"👤 {user}\n"
        f"🔐 Status: {label}\n"
        f"🕒 Time: {ts}"
    )
    send_telegram(msg)

# ── SCAN LOOP ──
def scan():
    for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline']):
        try:
            exe = proc.info.get('exe', '')
            if not exe or not os.path.isfile(exe):
                continue

            raw_cmdline = proc.info.get('cmdline', [])
            joined_cmd = ' '.join(raw_cmdline).lower() if isinstance(raw_cmdline, list) else str(raw_cmdline).lower()

            # ✅ Quarantine only if Start-Sleep is detected
            if "start-sleep" in joined_cmd:
                status = quarantine(exe, proc.info['pid'])
                log_alert(proc, "Suspicious: Start-Sleep usage", status)

            # 🔔 Alert-only for powershell executions
            elif "powershell" in joined_cmd or "powershell.exe" in exe.lower():
                log_alert(proc, "Alert: Powershell execution", "No")

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logging.warning(f"[SCAN SKIP] Process access issue: {e}")
            continue
        
def is_enabled():
    cfg = configparser.ConfigParser()
    cfg.read(STATE_FILE)
    return cfg.get("Monitor", "status", fallback="OFF") == "ON"

# ── MAIN ──
if __name__ == "__main__":
    print("🧠 Threat Monitor is ACTIVE")
    while True:
        if is_enabled():
            scan()
        else:
            print("⏸️ Monitoring paused")
        time.sleep(SCAN_INTERVAL)
