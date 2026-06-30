import os
import time
import json
import base64
import subprocess
import urllib.parse
import threading
import requests
import sqlite3
import io
import telebot
import matplotlib
matplotlib.use('Agg') # تنظیم موتور گرافیکی برای کار روی سرور لینوکس (بدون مانیتور)
import matplotlib.pyplot as plt
from telebot.types import ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardMarkup, InlineKeyboardButton

# ==========================================
# خواندن تنظیمات
# ==========================================
SETTINGS_FILE = "settings.json"
SERVERS_FILE = "servers.txt"
DB_FILE = "stats.db"

with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
    SETTINGS = json.load(f)

BOT_TOKEN = SETTINGS["telegram_bot_token"]
TELEGRAM_PROXY = SETTINGS.get("telegram_proxy", "")
ADMIN_IDS = [str(i).strip() for i in str(SETTINGS["telegram_chat_id"]).split(",") if str(i).strip()]

if TELEGRAM_PROXY:
    telebot.apihelper.proxy = {'http': TELEGRAM_PROXY, 'https': TELEGRAM_PROXY}

bot = telebot.TeleBot(BOT_TOKEN)
BOT_XRAY_PORT = 10809
test_lock = threading.Lock()
user_states = {}

# ==========================================
# توابع کمکی فایل و مدیریت
# ==========================================
def is_admin(user_id):
    return str(user_id) in ADMIN_IDS

def get_servers():
    """خواندن تمام کانفیگ‌های معتبر (روشن، خاموش و قرنطینه) از فایل"""
    if not os.path.exists(SERVERS_FILE):
        return []
    valid_servers = []
    with open(SERVERS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            
            test_line = line
            if line.startswith("#QUARANTINE#"):
                test_line = line[12:].strip()
            elif line.startswith("#"):
                test_line = line[1:].strip()
                
            if test_line.startswith(("ss://", "vmess://", "vless://", "trojan://")):
                valid_servers.append(line)
    return valid_servers

def save_servers(servers_list):
    with open(SERVERS_FILE, "w", encoding="utf-8") as f:
        for s in servers_list:
            f.write(s + "\n")

# ==========================================
# موتور رسم نمودار
# ==========================================
def generate_chart():
    """خواندن دیتابیس و رسم نمودار پینگ و سرعت"""
    try:
        if not os.path.exists(DB_FILE):
            return None
            
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT tag, AVG(ping), AVG(speed_mbps) 
            FROM stats 
            WHERE status='متصل' 
            GROUP BY tag
        ''')
        data = cursor.fetchall()
        conn.close()

        if not data:
            return None

        tags = [row[0] for row in data]
        pings = [row[1] for row in data]
        speeds = [row[2] for row in data]

        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))

        ax1.bar(tags, pings, color='skyblue', edgecolor='dodgerblue')
        ax1.set_title('Average Ping (ms) - Lower is better', fontsize=12)
        ax1.set_ylabel('Ping (ms)')
        ax1.tick_params(axis='x', rotation=45)
        ax1.grid(axis='y', linestyle='--', alpha=0.7)

        ax2.bar(tags, speeds, color='lightgreen', edgecolor='forestgreen')
        ax2.set_title('Average Download Speed (Mbps) - Higher is better', fontsize=12)
        ax2.set_ylabel('Speed (Mbps)')
        ax2.tick_params(axis='x', rotation=45)
        ax2.grid(axis='y', linestyle='--', alpha=0.7)

        plt.tight_layout()
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100)
        buf.seek(0)
        plt.close(fig)
        return buf
        
    except Exception as e:
        print(f"Chart Error: {e}")
        return None

# ==========================================
# مبدل لینک‌های تمام پروتکل‌ها
# ==========================================
def parse_config_url(url):
    url = url.strip()
    is_disabled = False
    is_quarantined = False
    
    if url.startswith("#QUARANTINE#"):
        is_quarantined = True
        is_disabled = True
        url = url[12:].strip()
    elif url.startswith("#"):
        is_disabled = True
        url = url[1:].strip()
        
    try:
        if url.startswith("ss://"):
            raw = url[5:]
            tag = urllib.parse.unquote(raw.split("#", 1)[1]) if "#" in raw else "Shadowsocks"
            return {"type": "SS", "tag": tag, "url": url, "disabled": is_disabled, "quarantined": is_quarantined}
        elif url.startswith("vmess://"):
            b64_str = url[8:]
            b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
            data = json.loads(base64.b64decode(b64_str).decode('utf-8'))
            return {"type": "VMess", "tag": data.get("ps", "بدون نام"), "url": url, "disabled": is_disabled, "quarantined": is_quarantined}
        elif url.startswith("vless://"):
            parsed = urllib.parse.urlparse(url)
            tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "VLESS"
            return {"type": "VLESS", "tag": tag, "url": url, "disabled": is_disabled, "quarantined": is_quarantined}
        elif url.startswith("trojan://"):
            parsed = urllib.parse.urlparse(url)
            tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Trojan"
            return {"type": "Trojan", "tag": tag, "url": url, "disabled": is_disabled, "quarantined": is_quarantined}
    except:
        pass
    return None

def build_xray_outbound(url):
    url = url.strip()
    if url.startswith("#QUARANTINE#"):
        url = url[12:].strip()
    elif url.startswith("#"):
        url = url[1:].strip()
        
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
            return outbound

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
            if is_vless:
                outbound["settings"] = {"vnext": [{"address": server, "port": port, "users": [{"id": creds, "encryption": qs.get("encryption", ["none"])[0], "flow": qs.get("flow", [""])[0]}]}]}
            else:
                outbound["settings"] = {"servers": [{"address": server, "port": port, "password": creds}]}

            stream = {"network": qs.get("type", ["tcp"])[0]}
            security = qs.get("security", ["none"])[0]
            stream["security"] = security
            if security == "tls":
                stream["tlsSettings"] = {"serverName": qs.get("sni", [server])[0], "fingerprint": qs.get("fp", ["chrome"])[0]}
            elif security == "reality":
                stream["realitySettings"] = {"serverName": qs.get("sni", [server])[0], "publicKey": qs.get("pbk", [""])[0], "shortId": qs.get("sid", [""])[0], "fingerprint": qs.get("fp", ["chrome"])[0], "spiderX": qs.get("spx", ["/"])[0]}
            if stream["network"] == "ws":
                stream["wsSettings"] = {"path": qs.get("path", ["/"])[0], "headers": {"Host": qs.get("host", [server])[0]}}
            elif stream["network"] == "grpc":
                stream["grpcSettings"] = {"serviceName": qs.get("serviceName", [""])[0], "multiMode": qs.get("mode", ["multi"])[0] == "multi"}
            outbound["streamSettings"] = stream
            return outbound

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
            outbound["settings"] = {"servers": [{"address": server, "port": int(port.split("/")[0].split("?")[0]), "method": method, "password": password}]}
            return outbound
            
    except Exception as e:
        print(f"Error parsing outbound: {e}")
        return None

def run_xray_test(url, test_type="ping", size_mb=100):
    outbound_config = build_xray_outbound(url)
    if not outbound_config:
        return {"success": False, "msg": "لینک نامعتبر یا پروتکل پشتیبانی نشده", "speed_mbps": 0, "ping": 0}

    config_file = f"bot_xray_temp_{int(time.time())}.json"
    xray_config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": BOT_XRAY_PORT, "listen": "127.0.0.1", "protocol": "socks"}],
        "outbounds": [outbound_config]
    }
    
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(xray_config, f)
        
    process = subprocess.Popen(["xray", "run", "-c", config_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2) 
    
    proxies = {"http": f"socks5h://127.0.0.1:{BOT_XRAY_PORT}", "https": f"socks5h://127.0.0.1:{BOT_XRAY_PORT}"}
    result = {"success": False, "msg": "", "speed_mbps": 0, "ping": 0}

    try:
        if test_type == "ping":
            ping_start = time.time()
            resp = requests.get("https://www.google.com/generate_204", proxies=proxies, timeout=7)
            if resp.status_code in [200, 204]:
                ping_ms = int((time.time() - ping_start) * 1000)
                result["success"] = True
                result["ping"] = ping_ms
                result["msg"] = f"متصل 🟢 ({ping_ms}ms)"
            else:
                result["msg"] = "پاسخ نامعتبر 🟡"
                
        elif test_type == "speed":
            ping_start = time.time()
            requests.get("https://www.google.com/generate_204", proxies=proxies, timeout=5)
            ping_ms = int((time.time() - ping_start) * 1000)
            
            url_dl = f"https://proof.ovh.net/files/1Gb.dat"
            start_time = time.time()
            resp = requests.get(url_dl, proxies=proxies, timeout=15, stream=True)
            resp.raise_for_status()
            
            downloaded = 0
            max_duration = 60 
            target_bytes = size_mb * 1024 * 1024 
            
            for chunk in resp.iter_content(chunk_size=65536):
                downloaded += len(chunk)
                if time.time() - start_time > max_duration or downloaded >= target_bytes:
                    break
                    
            duration = time.time() - start_time
            if duration > 0:
                speed_mbps = ((downloaded * 8) / duration) / 1000000
                result["success"] = True
                result["speed_mbps"] = round(speed_mbps, 2)
                result["ping"] = ping_ms
                result["msg"] = f"{result['speed_mbps']} Mbps 🚀"
                
    except requests.exceptions.RequestException:
        result["msg"] = "قطع 🔴 (Timeout)"
    finally:
        process.terminate()
        try: os.remove(config_file)
        except: pass
        
    return result

def get_server_status():
    try:
        with open('/proc/meminfo', 'r') as f:
            lines = f.readlines()
        total_ram = int(lines[0].split()[1]) / 1024
        free_ram = int(lines[2].split()[1]) / 1024
        used_ram = total_ram - free_ram
        with open('/proc/loadavg', 'r') as f:
            cpu_load = f.read().split()[0]
        return f"💻 <b>وضعیت سرور ایران:</b>\n\n⚙️ پردازنده (CPU): <code>{cpu_load}</code>\n🧠 کل رم: <code>{int(total_ram)} MB</code>\n📊 رم مصرفی: <code>{int(used_ram)} MB</code>"
    except:
        return "❌ خطا در خواندن وضعیت سرور"

# ==========================================
# دکمه‌ها و کیبوردها
# ==========================================
def main_menu():
    markup = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(KeyboardButton("🚀 تست سرعت"), KeyboardButton("🔌 تست اتصال"))
    markup.add(KeyboardButton("📋 لیست کانفیگ‌ها"), KeyboardButton("⚙️ مدیریت کانفیگ‌ها"))
    markup.add(KeyboardButton("💻 وضعیت سرور"), KeyboardButton("📈 نمودار پایداری"))
    return markup

def manage_menu():
    markup = InlineKeyboardMarkup(row_width=2)
    markup.add(
        InlineKeyboardButton("➕ افزودن کانفیگ", callback_data="mgr_add"),
        InlineKeyboardButton("✏️ ویرایش", callback_data="mgr_edit")
    )
    markup.add(
        InlineKeyboardButton("🗑 حذف کانفیگ", callback_data="mgr_del"),
        InlineKeyboardButton("🔄 روشن/خاموش", callback_data="mgr_toggle")
    )
    return markup

# ==========================================
# هندلرهای پیام اصلی
# ==========================================
@bot.message_handler(commands=['start', 'cancel'])
def send_welcome(message):
    if not is_admin(message.chat.id): return
    if message.chat.id in user_states: del user_states[message.chat.id]
    bot.reply_to(message, "سلام قربان! 🫡\nبه ربات دستیار مانیتورینگ خوش آمدید.\nیکی از گزینه‌ها را انتخاب کنید:", reply_markup=main_menu())

@bot.message_handler(func=lambda message: is_admin(message.chat.id) and message.text == "💻 وضعیت سرور")
def handle_server_status(message):
    bot.send_message(message.chat.id, get_server_status(), parse_mode="HTML")

@bot.message_handler(func=lambda message: is_admin(message.chat.id) and message.text == "📋 لیست کانفیگ‌ها")
def handle_list(message):
    servers = get_servers()
    if not servers:
        bot.send_message(message.chat.id, "❌ فایلی یافت نشد یا لیست خالی است.")
        return
    msg = "📋 <b>لیست تمام کانفیگ‌ها:</b>\n\n"
    for i, s in enumerate(servers):
        data = parse_config_url(s)
        if data:
            tag = data['tag']
            proto = data['type']
            status = "🚷 (قرنطینه)" if data.get('quarantined') else ("🔴 (خاموش)" if data.get('disabled') else "🟢 (روشن)")
            msg += f"{i+1}. <b>{tag}</b> [<code>{proto}</code>] - {status}\n"
    bot.send_message(message.chat.id, msg, parse_mode="HTML")

@bot.message_handler(func=lambda message: is_admin(message.chat.id) and message.text == "⚙️ مدیریت کانفیگ‌ها")
def handle_manage(message):
    bot.send_message(message.chat.id, "🛠 <b>بخش مدیریت کانفیگ‌ها:</b>\nچه کاری می‌خواهید انجام دهید؟", reply_markup=manage_menu(), parse_mode="HTML")

@bot.message_handler(func=lambda message: is_admin(message.chat.id) and message.text == "📈 نمودار پایداری")
def handle_chart(message):
    msg = bot.send_message(message.chat.id, "⏳ در حال خواندن دیتابیس و رسم نمودار...", parse_mode="HTML")
    
    def run_chart():
        buf = generate_chart()
        if buf:
            bot.send_photo(message.chat.id, buf, caption="📊 <b>گزارش میانگین پایداری سرورها</b>\nاین نمودار بر اساس تست‌های دوره‌ای ذخیره شده رسم شده است.", parse_mode="HTML")
            bot.delete_message(message.chat.id, msg.message_id)
        else:
            bot.edit_message_text("❌ هنوز دیتای کافی در دیتابیس ثبت نشده است.\nلطفاً منتظر بمانید تا تست‌های خودکار مانیتورینگ چند بار انجام شوند.", message.chat.id, msg.message_id)
            
    threading.Thread(target=run_chart).start()

@bot.message_handler(func=lambda message: is_admin(message.chat.id) and message.text == "🔌 تست اتصال")
def handle_ping_menu(message):
    servers = get_servers()
    if not servers:
        bot.send_message(message.chat.id, "❌ لیستی برای تست وجود ندارد.")
        return
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("🌟 تست همه کانفیگ‌ها 🌟", callback_data="ping_all"))
    for i, s in enumerate(servers):
        data = parse_config_url(s)
        if data:
            status_icon = "🚷" if data.get('quarantined') else ("🔴" if data.get('disabled') else "🟢")
            markup.add(InlineKeyboardButton(f"{status_icon} تست {data['tag']}", callback_data=f"ping_one_{i}"))
    bot.send_message(message.chat.id, "یکی از گزینه‌های زیر را برای تست اتصال (پینگ) انتخاب کنید:\n(می‌توانید کانفیگ‌های خاموش را هم دستی تست کنید)", reply_markup=markup)

@bot.message_handler(func=lambda message: is_admin(message.chat.id) and message.text == "🚀 تست سرعت")
def handle_speed_menu(message):
    servers = get_servers()
    if not servers:
        bot.send_message(message.chat.id, "❌ لیستی برای تست وجود ندارد.")
        return
    markup = InlineKeyboardMarkup()
    for i, s in enumerate(servers):
        data = parse_config_url(s)
        if data:
            status_icon = "🚷" if data.get('quarantined') else ("🔴" if data.get('disabled') else "🟢")
            markup.add(InlineKeyboardButton(f"{status_icon} 🚀 {data['tag']}", callback_data=f"sp_sel_{i}"))
    bot.send_message(message.chat.id, "کدام کانفیگ را می‌خواهید تست سرعت بگیرید؟", reply_markup=markup)

# ==========================================
# هندلرهای مدیریت کانفیگ‌ها (State Handlers)
# ==========================================
def process_add_step(message):
    if message.text == '/cancel': return send_welcome(message)
    new_url = message.text.strip()
    if not parse_config_url(new_url):
        bot.send_message(message.chat.id, "❌ لینک ارسالی نامعتبر است (پشتیبانی: vless, vmess, trojan, ss).\nعملیات لغو شد.")
        return
    servers = get_servers()
    servers.append(new_url)
    save_servers(servers)
    bot.send_message(message.chat.id, "✅ کانفیگ جدید با موفقیت به لیست اضافه شد.")

def process_del_step(message):
    if message.text == '/cancel': return send_welcome(message)
    try:
        idx = int(message.text.strip()) - 1
        servers = get_servers()
        if 0 <= idx < len(servers):
            removed = parse_config_url(servers[idx])
            tag = removed['tag'] if removed else "Unknown"
            servers.pop(idx)
            save_servers(servers)
            bot.send_message(message.chat.id, f"✅ کانفیگ <b>{tag}</b> با موفقیت حذف شد.", parse_mode="HTML")
        else:
            bot.send_message(message.chat.id, "❌ شماره وارد شده در لیست وجود ندارد. لغو شد.")
    except:
        bot.send_message(message.chat.id, "❌ لطفاً فقط یک عدد معتبر ارسال کنید. لغو شد.")

def process_edit_step_1(message):
    if message.text == '/cancel': return send_welcome(message)
    try:
        idx = int(message.text.strip()) - 1
        servers = get_servers()
        if 0 <= idx < len(servers):
            user_states[message.chat.id] = {"action": "editing", "index": idx}
            msg = bot.send_message(message.chat.id, "لطفاً لینک جدید کانفیگ را ارسال کنید:\n(برای لغو /cancel را بفرستید)")
            bot.register_next_step_handler(msg, process_edit_step_2)
        else:
            bot.send_message(message.chat.id, "❌ شماره نامعتبر است. لغو شد.")
    except:
        bot.send_message(message.chat.id, "❌ خطا. لغو شد.")

def process_edit_step_2(message):
    if message.text == '/cancel': return send_welcome(message)
    state = user_states.get(message.chat.id)
    if not state or state.get("action") != "editing": return
    
    new_url = message.text.strip()
    if not parse_config_url(new_url):
        bot.send_message(message.chat.id, "❌ لینک ارسالی نامعتبر است. عملیات لغو شد.")
        del user_states[message.chat.id]
        return
        
    servers = get_servers()
    idx = state["index"]
    if 0 <= idx < len(servers):
        servers[idx] = new_url
        save_servers(servers)
        bot.send_message(message.chat.id, "✅ کانفیگ با موفقیت ویرایش شد.")
    del user_states[message.chat.id]

# ==========================================
# هندلرهای کال‌بک دکمه‌های شیشه‌ای
# ==========================================
@bot.callback_query_handler(func=lambda call: is_admin(call.message.chat.id))
def handle_callbacks(call):
    data = call.data
    servers = get_servers()

    if data == "mgr_add":
        msg = bot.send_message(call.message.chat.id, "🔗 لطفاً لینک کانفیگ جدید (Vless/Vmess/Trojan/SS) را ارسال کنید:\n(برای لغو /cancel را بزنید)")
        bot.register_next_step_handler(msg, process_add_step)
        bot.answer_callback_query(call.id)
        
    elif data == "mgr_del":
        if not servers: return bot.send_message(call.message.chat.id, "لیست خالی است.")
        txt = "برای حذف، <b>شماره کانفیگ</b> را بفرستید:\n\n"
        for i, s in enumerate(servers):
            p = parse_config_url(s)
            txt += f"{i+1}. {p['tag'] if p else 'نامعتبر'}\n"
        msg = bot.send_message(call.message.chat.id, txt + "\n(برای لغو /cancel را بزنید)", parse_mode="HTML")
        bot.register_next_step_handler(msg, process_del_step)
        bot.answer_callback_query(call.id)
        
    elif data == "mgr_edit":
        if not servers: return bot.send_message(call.message.chat.id, "لیست خالی است.")
        txt = "برای ویرایش، <b>شماره کانفیگ</b> را بفرستید:\n\n"
        for i, s in enumerate(servers):
            p = parse_config_url(s)
            txt += f"{i+1}. {p['tag'] if p else 'نامعتبر'}\n"
        msg = bot.send_message(call.message.chat.id, txt + "\n(برای لغو /cancel را بزنید)", parse_mode="HTML")
        bot.register_next_step_handler(msg, process_edit_step_1)
        bot.answer_callback_query(call.id)
        
    elif data == "mgr_toggle":
        if not servers: return bot.send_message(call.message.chat.id, "لیست خالی است.")
        markup = InlineKeyboardMarkup()
        for i, s in enumerate(servers):
            p = parse_config_url(s)
            if p:
                status = "🚷" if p.get('quarantined') else ("🔴" if p.get('disabled') else "🟢")
                markup.add(InlineKeyboardButton(f"{status} {p['tag']}", callback_data=f"toggle_{i}"))
        markup.add(InlineKeyboardButton("🔙 بازگشت", callback_data="mgr_back"))
        bot.edit_message_text("تغییر وضعیت (با کلیک):\n\n🟢 = روشن\n🔴 = خاموش\n🚷 = قرنطینه (با کلیک دوباره روشن می‌شود)", 
                              call.message.chat.id, call.message.message_id, reply_markup=markup)

    elif data.startswith("toggle_"):
        idx = int(data.split("_")[1])
        if 0 <= idx < len(servers):
            url = servers[idx].strip()
            
            # منطق سوییچ کردن حالت
            if url.startswith("#QUARANTINE#"):
                servers[idx] = url[12:].strip() # بازگشت به حالت عادی
            elif url.startswith("#"):
                servers[idx] = url[1:].strip() # بازگشت به حالت عادی
            else:
                servers[idx] = "#" + url # خاموش کردن دستی
                
            save_servers(servers)
            
            markup = InlineKeyboardMarkup()
            for i, s in enumerate(servers):
                p = parse_config_url(s)
                if p:
                    status = "🚷" if p.get('quarantined') else ("🔴" if p.get('disabled') else "🟢")
                    markup.add(InlineKeyboardButton(f"{status} {p['tag']}", callback_data=f"toggle_{i}"))
            markup.add(InlineKeyboardButton("🔙 بازگشت", callback_data="mgr_back"))
            bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=markup)

    elif data == "mgr_back":
        bot.edit_message_text("🛠 <b>بخش مدیریت کانفیگ‌ها:</b>\nچه کاری می‌خواهید انجام دهید؟", 
                              call.message.chat.id, call.message.message_id, reply_markup=manage_menu(), parse_mode="HTML")

    elif data.startswith("sp_sel_"):
        idx = int(data.split("_")[2])
        conf = parse_config_url(servers[idx])
        if not conf: return
        markup = InlineKeyboardMarkup()
        markup.add(InlineKeyboardButton("100 مگابایت", callback_data=f"sp_run_{idx}_100"),
                   InlineKeyboardButton("250 مگابایت", callback_data=f"sp_run_{idx}_250"))
        bot.edit_message_text(f"حجم فایل تستی برای <b>{conf['tag']}</b> را انتخاب کنید:", 
                              call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="HTML")

    elif data.startswith("sp_run_"):
        parts = data.split("_")
        idx = int(parts[2])
        size = int(parts[3])
        url = servers[idx]
        conf = parse_config_url(url)
        
        bot.edit_message_text(f"⏳ در حال تست سرعت <b>{conf['tag']}</b> (حجم {size}MB)...\n<i>لطفاً تا ۱ دقیقه صبور باشید.</i>", 
                              call.message.chat.id, call.message.message_id, parse_mode="HTML")
        
        def run_task():
            with test_lock: 
                res = run_xray_test(url, test_type="speed", size_mb=size)
            
            if res["success"]:
                text = (f"📊 <b>نتیجه تست سرعت:</b>\n\n"
                        f"📌 <b>کانفیگ:</b> {conf['tag']}\n"
                        f"📦 <b>حجم تست:</b> {size}MB\n"
                        f"⚡ <b>پینگ:</b> {res['ping']} ms\n"
                        f"🚀 <b>سرعت:</b> {res['speed_mbps']} Mbps")
            else:
                text = (f"📊 <b>نتیجه تست سرعت:</b>\n\n"
                        f"📌 <b>کانفیگ:</b> {conf['tag']}\n"
                        f"📦 <b>حجم تست:</b> {size}MB\n"
                        f"نتیجه: <b>{res['msg']}</b>")
                        
            bot.send_message(call.message.chat.id, text, parse_mode="HTML")
            
        threading.Thread(target=run_task).start()

    elif data.startswith("ping_one_"):
        idx = int(data.split("_")[2])
        url = servers[idx]
        conf = parse_config_url(url)
        bot.edit_message_text(f"⏳ در حال بررسی <b>{conf['tag']}</b>...", call.message.chat.id, call.message.message_id, parse_mode="HTML")
        
        def run_task():
            with test_lock:
                res = run_xray_test(url, test_type="ping")
            bot.send_message(call.message.chat.id, f"📌 وضعیت <b>{conf['tag']}</b>: {res['msg']}", parse_mode="HTML")
            
        threading.Thread(target=run_task).start()

    elif data == "ping_all":
        bot.edit_message_text("⏳ در حال بررسی تمام کانفیگ‌ها به نوبت...\n<i>کمی زمان می‌برد.</i>", call.message.chat.id, call.message.message_id, parse_mode="HTML")
        
        def run_task():
            msg = "📊 <b>گزارش وضعیت تمام سرورها:</b>\n\n"
            with test_lock:
                for s in servers:
                    conf = parse_config_url(s)
                    if conf:
                        res = run_xray_test(s, test_type="ping")
                        msg += f"🔹 {conf['tag']}: <b>{res['msg']}</b>\n"
            bot.send_message(call.message.chat.id, msg, parse_mode="HTML")
            
        threading.Thread(target=run_task).start()

if __name__ == "__main__":
    print("🤖 ربات تلگرامی دستیار روشن شد... منتظر پیام شماست!")
    while True:
        try:
            bot.polling(non_stop=True, timeout=60)
        except Exception as e:
            print(f"[-] ارور اتصال در ربات: {e}")
            time.sleep(5)