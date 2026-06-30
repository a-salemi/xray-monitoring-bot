#!/bin/bash

# ==========================================
# Xray & Shadowsocks Monitoring Bot Installer
# Created by: Amir Salemi
# GitHub: https://github.com/a-salemi/xray-monitoring-bot
# ==========================================

echo -e "\e[36m=========================================\e[0m"
echo -e "\e[1;36m  Xray Monitoring Bot Installer\e[0m"
echo -e "\e[1;34m  By: Amir Salemi\e[0m"
echo -e "\e[36m=========================================\e[0m"
sleep 2

# بررسی دسترسی روت (Root)
if [ "$EUID" -ne 0 ]; then
  echo -e "\e[31m[-] لطفا این اسکریپت را با دسترسی root اجرا کنید (sudo -i)\e[0m"
  exit
fi

echo -e "\e[32m[+] در حال بروزرسانی مخازن سیستم...\e[0m"
apt-get update -y

echo -e "\e[32m[+] در حال نصب پیش‌نیازهای پایتون و ابزارهای شبکه...\e[0m"
apt-get install -y python3 python3-pip curl wget jq git

echo -e "\e[32m[+] در حال نصب کتابخانه‌های پایتون...\e[0m"
pip3 install pyTelegramBotAPI requests matplotlib

echo -e "\e[32m[+] در حال نصب هسته Xray...\e[0m"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# ایجاد پوشه پروژه
INSTALL_DIR="/root/ss-monitor"
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

echo -e "\e[34m=========================================\e[0m"
echo -e "\e[36mتنظیمات ربات تلگرام\e[0m"
echo -e "\e[34m=========================================\e[0m"

read -p "لطفا توکن ربات تلگرام خود را وارد کنید (Bot Token): " BOT_TOKEN
read -p "لطفا آیدی عددی اکانت تلگرام خود را وارد کنید (Admin Chat ID): " CHAT_ID

# ساخت فایل تنظیمات
echo -e "\e[32m[+] در حال ساخت فایل تنظیمات (settings.json)...\e[0m"
cat > settings.json <<EOF
{
  "telegram_bot_token": "$BOT_TOKEN",
  "telegram_chat_id": "$CHAT_ID",
  "telegram_proxy": "",
  "check_interval_seconds": 300,
  "max_retries": 4,
  "retry_delay_seconds": 3,
  "test_url": "https://www.google.com/generate_204",
  "speed_test_interval_seconds": 3600,
  "speed_test_url": "https://proof.ovh.net/files/10Mb.dat",
  "min_speed_mbps": 20
}
EOF

# ساخت فایل لیست سرورها
if [ ! -f "servers.txt" ]; then
    echo "# لینک‌های کانفیگ خود را در این فایل قرار دهید" > servers.txt
fi

# دانلود سورس کدها از گیت‌هاب شما
echo -e "\e[32m[+] در حال دریافت فایل‌های سورس از گیت‌هاب...\e[0m"
wget -qO monitor.py https://raw.githubusercontent.com/a-salemi/xray-monitoring-bot/main/monitor.py
wget -qO bot.py https://raw.githubusercontent.com/a-salemi/xray-monitoring-bot/main/bot.py

# ساخت سرویس مانیتورینگ
echo -e "\e[32m[+] در حال ساخت سرویس‌های لینوکس...\e[0m"
cat > /etc/systemd/system/ss-monitor.service <<EOF
[Unit]
Description=Shadowsocks Monitoring Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/monitor.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# ساخت سرویس ربات تلگرام
cat > /etc/systemd/system/ss-bot.service <<EOF
[Unit]
Description=Shadowsocks Telegram Bot Assistant
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/bot.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# فعال‌سازی و اجرای سرویس‌ها
systemctl daemon-reload
systemctl enable ss-monitor
systemctl enable ss-bot
systemctl start ss-monitor
systemctl start ss-bot

echo -e "\e[34m=========================================\e[0m"
echo -e "\e[32m✅ نصب با موفقیت به پایان رسید!\e[0m"
echo -e "\e[33mربات شما اکنون در تلگرام روشن است. لطفا دستور /start را در ربات خود ارسال کنید.\e[0m"
echo -e "\e[34m=========================================\e[0m"