# 1) بکاپ از فایل فعلی
cp -a /opt/dns-proxy/nftables/dns_enforced.nft{,.bak-$(date +%F-%H%M)}

# 2) جایگزینی با محتوای صحیح (سینتکس درست: set/chain، اولویت بالاتر، counters و مسدودسازی IPv6)
cat > /opt/dns-proxy/nftables/dns_enforced.nft <<'EOF'
table inet filter {
  set allow_dns_clients { type ipv4_addr; flags interval; }
  chain input {
    type filter hook input priority -100;
    ct state established,related accept
    iif lo accept
    # SSH
    tcp dport 22 accept
    # DNS فقط برای کلاینت‌های allowlist
    udp dport 53 ip saddr @allow_dns_clients counter accept
    tcp dport 53 ip saddr @allow_dns_clients counter accept
    # سایر DNS ها مسدود
    udp dport 53 counter drop
    tcp dport 53 counter drop
    # جلوگیری از دورزدن با IPv6 DNS
    udp dport 53 ip6 saddr ::/0 counter drop
    tcp dport 53 ip6 saddr ::/0 counter drop
    # سایر ترافیک‌ها پذیرفته شود (مطابق سیاست فعلی)
    accept
  }
}
EOF

# 3) اعمال قوانین
# حالت عادی:
nft -f /opt/dns-proxy/nftables/dns_enforced.nft

# در صورتی که به خاطر وجود قبلی table خطا گرفت:
# (هشدار: این جدول inet:filter را پاک می‌کند. فرض ما این است که فقط dns-loki از آن استفاده می‌کند.)
# nft delete table inet filter || true
# nft -f /opt/dns-proxy/nftables/dns_enforced.nft

# 4) بررسی سریع
nft list chain inet filter input
nft list set inet filter allow_dns_clients



# 1) بکاپ از فایل‌های زنده‌ی کنترلر
mkdir -p /opt/dns-proxy/backup/controller-$(date +%F-%H%M)
cp -a /opt/dns-proxy/controller /opt/dns-proxy/backup/controller-$(date +%F-%H%M)/

# 2) کپی فایل‌های جدید کنترلر و UI
install -m 0644 ~/dns-loki/controller/api.py /opt/dns-proxy/controller/api.py
install -m 0644 ~/dns-loki/controller/requirements.txt /opt/dns-proxy/controller/requirements.txt
rm -rf /opt/dns-proxy/controller/ui
cp -a ~/dns-loki/controller/ui /opt/dns-proxy/controller/ui

# 3) نصب وابستگی‌ها داخل venv کنترلر
/opt/dns-proxy/controller/venv/bin/pip install -r /opt/dns-proxy/controller/requirements.txt

# 4) ری‌استارت کنترلر
systemctl restart dns-proxy-controller

# 5) بررسی وضعیت و لاگ‌ها
systemctl status --no-pager -l dns-proxy-controller
journalctl -u dns-proxy-controller -n 100 --no-pager