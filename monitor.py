import os
import time
import json
import base64
import subprocess
import urllib.parse
import requests
import sqlite3
import concurrent.futures
import threading

with open("settings.json", "r", encoding="utf-8") as f:
    SETTINGS = json.load(f)

BOT_TOKEN = SETTINGS["telegram_bot_token"]
CHAT_ID = SETTINGS["telegram_chat_id"]
TELEGRAM_PROXY = SETTINGS.get("telegram_proxy", "")
CHECK_INTERVAL = SETTINGS["check_interval_seconds"]
MAX_RETRIES = SETTINGS["max_retries"]
RETRY_DELAY = SETTINGS["retry_delay_seconds"]
TEST_URL = SETTINGS["test_url"]
SPEED_TEST_INTERVAL = SETTINGS.get("speed_test_interval_seconds", 3600)
SPEED_TEST_URL = SETTINGS.get("speed_test_url", "https://proof.ovh.net/files/10Mb.dat")
MIN_SPEED_MBPS = SETTINGS.get("min_speed_mbps", SETTINGS.get("min_speed_kbps", 20000) / 1000)
XRAY_PORT = 10808

last_speed_test_time = 0
db_lock = threading.Lock()
config_lock = threading.Lock()

# ذخیره تعداد خطاهای پیاپی برای سیستم قرنطینه
failure_counts = {}
MAX_FAILURES_BEFORE_QUARANTINE = 3

def init_db():
    with db_lock:
        conn = sqlite3.connect("stats.db", check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS stats (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, tag TEXT, address TEXT, ping INTEGER, speed_mbps REAL, status TEXT)''')
        conn.commit()
        conn.close()

def log_stat(tag, address, ping, speed_mbps, status):
    with db_lock:
        try:
            conn = sqlite3.connect("stats.db", timeout=10)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO stats (tag, address, ping, speed_mbps, status) VALUES (?, ?, ?, ?, ?)', (tag, address, ping, speed_mbps, status))
            conn.commit()
            conn.close()
        except: pass

def send_telegram_alert(message):
    if not BOT_TOKEN or not CHAT_ID: return
    chat_ids = CHAT_ID if isinstance(CHAT_ID, list) else [c.strip() for c in str(CHAT_ID).split(",") if c.strip()]
    proxies = {"http": TELEGRAM_PROXY, "https": TELEGRAM_PROXY} if TELEGRAM_PROXY else None
    for cid in chat_ids:
        try:
            requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", json={"chat_id": cid, "text": message, "parse_mode": "HTML"}, proxies=proxies, timeout=15)
        except: pass

def parse_config_url(url):
    url = url.strip()
    try:
        if url.startswith("ss://"):
            raw = url[5:]
            tag = urllib.parse.unquote(raw.split("#", 1)[1]) if "#" in raw else "Shadowsocks"
            return {"type": "SS", "tag": tag, "url": url}
        elif url.startswith("vmess://"):
            b64_str = url[8:]
            b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
            data = json.loads(base64.b64decode(b64_str).decode('utf-8'))
            return {"type": "VMess", "tag": data.get("ps", "بدون نام"), "url": url}
        elif url.startswith("vless://"):
            parsed = urllib.parse.urlparse(url)
            tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "VLESS"
            return {"type": "VLESS", "tag": tag, "url": url}
        elif url.startswith("trojan://"):
            parsed = urllib.parse.urlparse(url)
            tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Trojan"
            return {"type": "Trojan", "tag": tag, "url": url}
    except: pass
    return None

def build_xray_outbound(url):
    url = url.strip()
    outbound = {"tag": "proxy"}
    try:
        if url.startswith("vmess://"):
            b64_str = url[8:]
            b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
            data = json.loads(base64.b64decode(b64_str).decode('utf-8'))
            outbound["protocol"] = "vmess"
            outbound["settings"] = {"vnext": [{"address": data.get("add", ""), "port": int(data.get("port", 443)), "users": [{"id": data.get("id", ""), "alterId": int(data.get("aid", 0)), "security": "auto"}]}]}
            stream = {"network": data.get("net", "tcp")}
            if data.get("tls") == "tls":
                stream["security"] = "tls"
                stream["tlsSettings"] = {"serverName": data.get("sni", data.get("add"))}
            if data.get("net") == "ws":
                stream["wsSettings"] = {"path": data.get("path", "/"), "headers": {"Host": data.get("host", data.get("add"))}}
            elif data.get("net") == "grpc":
                stream["grpcSettings"] = {"serviceName": data.get("path", "")}
            outbound["streamSettings"] = stream
            return outbound, data.get("add", "")

        elif url.startswith("vless://") or url.startswith("trojan://"):
            is_vless = url.startswith("vless://")
            parsed = urllib.parse.urlparse(url)
            creds_server_port = parsed.netloc.split("@")
            creds = creds_server_port[0]
            server_port = creds_server_port[1].split(":")
            server = server_port[0]
            port = int(server_port[1])
            qs = urllib.parse.parse_qs(parsed.query)
            
            outbound["protocol"] = "vless" if is_vless else "trojan"
            if is_vless: outbound["settings"] = {"vnext": [{"address": server, "port": port, "users": [{"id": creds, "encryption": qs.get("encryption", ["none"])[0], "flow": qs.get("flow", [""])[0]}]}]}
            else: outbound["settings"] = {"servers": [{"address": server, "port": port, "password": creds}]}

            stream = {"network": qs.get("type", ["tcp"])[0]}
            security = qs.get("security", ["none"])[0]
            stream["security"] = security
            if security == "tls": stream["tlsSettings"] = {"serverName": qs.get("sni", [server])[0], "fingerprint": qs.get("fp", ["chrome"])[0]}
            elif security == "reality": stream["realitySettings"] = {"serverName": qs.get("sni", [server])[0], "publicKey": qs.get("pbk", [""])[0], "shortId": qs.get("sid", [""])[0], "fingerprint": qs.get("fp", ["chrome"])[0], "spiderX": qs.get("spx", ["/"])[0]}
            if stream["network"] == "ws": stream["wsSettings"] = {"path": qs.get("path", ["/"])[0], "headers": {"Host": qs.get("host", [server])[0]}}
            elif stream["network"] == "grpc": stream["grpcSettings"] = {"serviceName": qs.get("serviceName", [""])[0], "multiMode": qs.get("mode", ["multi"])[0] == "multi"}
            outbound["streamSettings"] = stream
            return outbound, f"{server}:{port}"

        elif url.startswith("ss://"):
            raw = url[5:]
            if "#" in raw: raw = raw.split("#", 1)[0]
            if "@" in raw:
                userinfo_b64, server_port = raw.split("@", 1)
                userinfo_b64 += "=" * ((4 - len(userinfo_b64) % 4) % 4)
                userinfo = base64.b64decode(userinfo_b64).decode('utf-8')
                method, password = userinfo.split(":", 1)
                server, port = server_port.split(":", 1)
            else:
                raw += "=" * ((4 - len(raw) % 4) % 4)
                decoded = base64.b64decode(raw).decode('utf-8')
                userinfo, server_port = decoded.split("@", 1)
                method, password = userinfo.split(":", 1)
                server, port = server_port.split(":", 1)
                
            outbound["protocol"] = "shadowsocks"
            port_num = int(port.split("/")[0].split("?")[0])
            outbound["settings"] = {"servers": [{"address": server, "port": port_num, "method": method, "password": password}]}
            return outbound, f"{server}:{port_num}"
    except: return None, ""

def run_speed_test(proxies, tag, server_addr):
    speed_mbps = 0.0
    try:
        start_time = time.time()
        response = requests.get(SPEED_TEST_URL, proxies=proxies, timeout=20, stream=True)
        response.raise_for_status()
        
        downloaded = sum(len(chunk) for chunk in response.iter_content(chunk_size=65536))
        duration = time.time() - start_time
        
        if duration > 0:
            speed_mbps = round(((downloaded * 8) / duration) / 1000000, 2)
            status_icon, status_text = ("🟢", "مطلوب") if speed_mbps >= MIN_SPEED_MBPS else ("⚠️", "ضعیف")
            send_telegram_alert(f"📊 <b>گزارش دوره‌ای تست سرعت</b>\n\n📌 <b>نام کانفیگ:</b> {tag}\n🌐 <b>آدرس:</b> <code>{server_addr}</code>\n🚀 <b>سرعت ثبت شده:</b> {speed_mbps} Mbps\n{status_icon} <b>وضعیت:</b> {status_text}")
    except: pass
    return speed_mbps

def quarantine_config(url, tag):
    """انتقال کانفیگ به لیست قرنطینه با ویرایش فایل متنی"""
    with config_lock:
        try:
            with open("servers.txt", "r", encoding="utf-8") as f:
                lines = f.readlines()
            with open("servers.txt", "w", encoding="utf-8") as f:
                for line in lines:
                    if line.strip() == url:
                        f.write(f"#QUARANTINE#{line.strip()}\n")
                    else:
                        f.write(line)
        except Exception as e:
            print(f"Error in quarantine: {e}")

def test_connection(url, should_run_speed_test, worker_port):
    conf_data = parse_config_url(url)
    if not conf_data: return False
    tag = conf_data["tag"]
    outbound_config, server_addr = build_xray_outbound(url)
    if not outbound_config: return False

    config_file = f"temp_conf_{worker_port}_{int(time.time())}.json"
    xray_config = {"log": {"loglevel": "none"}, "inbounds": [{"port": worker_port, "listen": "127.0.0.1", "protocol": "socks"}], "outbounds": [outbound_config]}
    
    with open(config_file, "w", encoding="utf-8") as f: json.dump(xray_config, f)
    xray_process = subprocess.Popen(["xray", "run", "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2) 
    
    proxies = {"http": f"socks5h://127.0.0.1:{worker_port}", "https": f"socks5h://127.0.0.1:{worker_port}"}
    success, ping_ms, speed_mbps, status_text = False, 0, 0.0, "قطع"
    
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            ping_start = time.time()
            if requests.get(TEST_URL, proxies=proxies, timeout=7).status_code in [200, 204]:
                success, ping_ms, status_text = True, int((time.time() - ping_start) * 1000), "متصل"
                break
        except requests.exceptions.RequestException:
            if attempt < MAX_RETRIES: time.sleep(RETRY_DELAY)

    if success and should_run_speed_test: speed_mbps = run_speed_test(proxies, tag, server_addr)

    xray_process.terminate()
    try: os.remove(config_file)
    except: pass

    log_stat(tag, server_addr, ping_ms, speed_mbps, status_text)

    # سیستم هوشمند قرنطینه
    if not success:
        with config_lock:
            failure_counts[url] = failure_counts.get(url, 0) + 1
            fails = failure_counts[url]
            
        if fails >= MAX_FAILURES_BEFORE_QUARANTINE:
            quarantine_config(url, tag)
            with config_lock: failure_counts[url] = 0
            send_telegram_alert(f"🚷 <b>قرنطینه خودکار</b>\n\n📌 <b>کانفیگ:</b> {tag}\nبه دلیل قطع بودن در {MAX_FAILURES_BEFORE_QUARANTINE} بررسی متوالی، از چرخه مانیتورینگ خارج شد.")
        else:
            send_telegram_alert(f"🚨 <b>هشدار قطعی سرور</b>\n\n📌 <b>کانفیگ:</b> {tag}\n❌ <b>وضعیت:</b> قطع می‌باشد! (اخطار {fails}/{MAX_FAILURES_BEFORE_QUARANTINE})")
    else:
        with config_lock:
            if url in failure_counts: failure_counts[url] = 0

    return success

def main():
    global last_speed_test_time
    init_db()
    print("🚀 مانیتورینگ با سیستم قرنطینه آغاز به کار کرد...")
    
    while True:
        try:
            current_time = time.time()
            should_run_speed_test = (current_time - last_speed_test_time) >= SPEED_TEST_INTERVAL
            
            with open("servers.txt", "r", encoding="utf-8") as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(test_connection, url, should_run_speed_test, 11000 + idx) for idx, url in enumerate(urls)]
                for future in concurrent.futures.as_completed(futures): pass
            
            if should_run_speed_test: last_speed_test_time = time.time()
            time.sleep(CHECK_INTERVAL)
            
        except Exception as e: time.sleep(60)

if __name__ == "__main__":
    main()