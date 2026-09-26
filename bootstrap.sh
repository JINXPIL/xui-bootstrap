#!/usr/bin/env bash
# xui-bootstrap: 3x-ui на VPS + маскировка + твои инбаунды.
set -Eeuo pipefail
shopt -u patsub_replacement 2>/dev/null || true

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XUI_BIN=/usr/local/x-ui/x-ui
RESULT=/root/xui-result.txt
exec > >(tee -a /var/log/xui-bootstrap.log) 2>&1

ok()   { printf '\033[32m[ok]\033[0m %s\n' "$*"; }
info() { printf '\033[36m[..]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!!]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[xx]\033[0m %s\n' "$*"; exit 1; }
trap 'die "Упало на строке $LINENO: $BASH_COMMAND"' ERR

# ---------- 0. проверки и конфиг ----------
[[ $EUID -eq 0 ]] || die "Нужен root"
. /etc/os-release
[[ "${ID:-} ${ID_LIKE:-}" =~ (debian|ubuntu) ]] || die "Только Debian/Ubuntu (у тебя ${PRETTY_NAME:-?})"
[[ -f $DIR/config.env ]] || die "Нет config.env"
# shellcheck source=/dev/null
. "$DIR/config.env"
MASK_MODE=${MASK_MODE:-reality}; BLOCK_RU=${BLOCK_RU:-1}; ENABLE_BBR=${ENABLE_BBR:-1}
SSH_KEYS_ONLY=${SSH_KEYS_ONLY:-0}; XUI_VERSION=${XUI_VERSION:-}; XRAY_VERSION=${XRAY_VERSION:-}
shopt -s nullglob; TEMPLATES=("$DIR"/inbounds/*.json); shopt -u nullglob
(( ${#TEMPLATES[@]} )) || die "В inbounds/ нет *.json"

# ---------- 1. пакеты ----------
export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -o DPkg::Lock::Timeout=600 -yq)
info "Пакеты…"
"${APT[@]}" update >/dev/null
PKGS=(curl ca-certificates jq ufw fail2ban python3-systemd bind9-dnsutils openssl tar)
if [[ $MASK_MODE == selfsteal ]]; then PKGS+=(nginx certbot); fi
"${APT[@]}" install "${PKGS[@]}" >/dev/null || "${APT[@]}" install curl ca-certificates jq ufw fail2ban dnsutils openssl tar >/dev/null

# ---------- 2. IP и параметры маски ----------
SERVER_IP=$(curl -4fsS --max-time 6 https://api.ipify.org || ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}' || true)
[[ -n $SERVER_IP ]] || die "Не определил IP сервера (задай SERVER_ADDR)"
case $MASK_MODE in
  reality)   [[ -n ${REALITY_SNI:-} ]] || die "Задай REALITY_SNI"
             SNI=$REALITY_SNI; DEST=${REALITY_DEST:-$REALITY_SNI:443}; PUBLIC_HOST=${SERVER_ADDR:-$SERVER_IP} ;;
  selfsteal) [[ -n ${DOMAIN:-} ]] || die "Задай DOMAIN"
             SNI=$DOMAIN; DEST=127.0.0.1:8443; PUBLIC_HOST=${SERVER_ADDR:-$DOMAIN} ;;
  *) die "MASK_MODE = reality | selfsteal" ;;
esac
render() { local t; t=$(<"$1"); t=${t//__SNI__/$SNI}; t=${t//__DEST__/$DEST}; printf '%s' "${t//__SERVER__/$PUBLIC_HOST}"; }

# ---------- 3. проверка шаблонов + какие порты открыть ----------
TCP_PORTS=(); UDP_PORTS=()
for f in "${TEMPLATES[@]}"; do
  j=$(render "$f"); n=$(basename "$f")
  jq -e '.port and .protocol' >/dev/null 2>&1 <<<"$j" || die "$n: не похоже на экспорт инбаунда"
  left=$(grep -oE '__[A-Z_]+__' <<<"$j" | sort -u | tr '\n' ' ' || true)
  [[ -z $left ]] || die "$n: не заполнено: $left"
  p=$(jq -r .port <<<"$j"); pr=$(jq -r .protocol <<<"$j")
  net=$(jq -r '.streamSettings | (if type=="string" then (fromjson? // {}) else (. // {}) end) | .network // "tcp"' <<<"$j")
  case "$pr:$net" in hysteria*|tuic*|wireguard*|amneziawg*|*:kcp) UDP_PORTS+=("$p");; *) TCP_PORTS+=("$p");; esac
done
ok "Шаблонов: ${#TEMPLATES[@]} (tcp: ${TCP_PORTS[*]:-—}, udp: ${UDP_PORTS[*]:-—})"

# ---------- 4. система ----------
timedatectl set-ntp true 2>/dev/null || warn "NTP не включился — Reality чувствителен ко времени"
if [[ $ENABLE_BBR == 1 ]]; then
  printf '%s\n' net.core.default_qdisc=fq net.ipv4.tcp_congestion_control=bbr net.ipv4.tcp_mtu_probing=1 > /etc/sysctl.d/99-xui.conf
  sysctl -q --system >/dev/null 2>&1 || warn "sysctl применился не полностью"
fi

# ---------- 5. SSH, фаервол, fail2ban ----------
mapfile -t SSH_PORTS < <( { sshd -T 2>/dev/null | awk '$1=="port"{print $2}'; if [[ -n ${SSH_CONNECTION:-} ]]; then echo "${SSH_CONNECTION##* }"; fi; } | sort -un )
(( ${#SSH_PORTS[@]} )) || SSH_PORTS=(22)
ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null
for p in "${SSH_PORTS[@]}"; do ufw allow "$p/tcp" comment ssh >/dev/null; done
for p in "${TCP_PORTS[@]}" ${EXTRA_TCP_PORTS:-}; do ufw allow "$p/tcp" comment xray >/dev/null; done
for p in "${UDP_PORTS[@]}" ${EXTRA_UDP_PORTS:-}; do ufw allow "$p/udp" comment xray >/dev/null; done
if [[ $MASK_MODE == selfsteal ]]; then ufw allow 80/tcp comment acme >/dev/null; fi
ufw --force enable >/dev/null
ok "Фаервол: снаружи только SSH (${SSH_PORTS[*]}) и порты инбаундов"

printf '[sshd]\nenabled = true\nbackend = systemd\nport = %s\nmaxretry = 5\nbantime = 1h\n' \
  "$(IFS=,; echo "${SSH_PORTS[*]}")" > /etc/fail2ban/jail.d/xui-sshd.local
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban || warn "fail2ban не поднялся"

if [[ $SSH_KEYS_ONLY == 1 ]]; then
  if [[ -s /root/.ssh/authorized_keys ]]; then
    mkdir -p /etc/ssh/sshd_config.d
    printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' > /etc/ssh/sshd_config.d/00-xui.conf
    if sshd -t; then systemctl reload ssh 2>/dev/null || systemctl reload sshd; ok "SSH: только по ключу"
    else rm -f /etc/ssh/sshd_config.d/00-xui.conf; warn "sshd -t не прошёл — откатил"; fi
  else warn "authorized_keys пуст — вход по паролю НЕ отключаю"; fi
fi

# ---------- 6. маскировка ----------
asn_of() {
  [[ ${1:-} =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 0
  dig +short +time=3 +tries=1 TXT "${BASH_REMATCH[4]}.${BASH_REMATCH[3]}.${BASH_REMATCH[2]}.${BASH_REMATCH[1]}.origin.asn.cymru.com" 2>/dev/null \
    | tr -d '"' | awk -F'|' 'NR==1{split($1,a," "); print a[1]}' || true
}
if [[ $MASK_MODE == reality ]]; then
  v=$(curl -s -o /dev/null --max-time 10 --tlsv1.3 --http2 -w '%{http_version}' "https://$SNI/" || true)
  if [[ $v == 2 ]]; then ok "Донор $SNI: TLS 1.3 + h2"; else warn "Донор $SNI не дал TLS1.3+h2 с этого сервера ($v) — Reality с ним не заработает"; fi
  a1=$(asn_of "$SERVER_IP"); a2=$(asn_of "$(getent ahostsv4 "$SNI" 2>/dev/null | awk 'NR==1{print $1}' || true)")
  if [[ -n $a1 && -n $a2 ]]; then
    if [[ $a1 == "$a2" ]]; then ok "Донор в той же AS$a1, что и VPS"
    else warn "Донор в AS$a2, VPS в AS$a1 — лучше донор из подсети/ASN своего хостера"; fi
  fi
fi

if [[ $MASK_MODE == selfsteal ]]; then
  ips=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
  [[ " $ips " == *" $SERVER_IP "* ]] || die "$DOMAIN → [${ips:-нет}], а сервер $SERVER_IP. Поправь A-запись (в Cloudflare — серое облако)"
  WEB=/var/www/decoy; mkdir -p "$WEB"
  if [[ -d $DIR/site ]]; then cp -r "$DIR/site/." "$WEB/"
  elif [[ ! -f $WEB/index.html ]]; then
    t=${DOMAIN%%.*}
    cat > "$WEB/index.html" <<EOC
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${t^}</title><style>body{font:16px/1.6 system-ui,sans-serif;max-width:640px;margin:10vh auto;padding:0 20px;color:#222}
footer{margin-top:4em;color:#888;font-size:14px}@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}}</style></head>
<body><h1>${t^}</h1><p>Personal notes, small tools and experiments. The new version of the site is on its way.</p>
<footer>&copy; $(date +%Y) ${DOMAIN}</footer></body></html>
EOC
  fi
  rm -f /etc/nginx/sites-enabled/default
  cat > /etc/nginx/conf.d/decoy.conf <<EOC
server {
    listen 80 default_server; listen [::]:80 default_server;
    server_tokens off;
    location /.well-known/acme-challenge/ { root $WEB; }
    location / { return 301 https://$DOMAIN\$request_uri; }
}
EOC
  nginx -t -q || die "nginx: битый конфиг"
  systemctl enable nginx >/dev/null 2>&1 || true; systemctl restart nginx
  if [[ ! -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]]; then
    em=(--register-unsafely-without-email); if [[ -n ${ACME_EMAIL:-} ]]; then em=(-m "$ACME_EMAIL"); fi
    certbot certonly --webroot -w "$WEB" -d "$DOMAIN" --agree-tos --non-interactive "${em[@]}" --deploy-hook "systemctl reload nginx"
  fi
  cat >> /etc/nginx/conf.d/decoy.conf <<EOC
server {
    listen 127.0.0.1:8443 ssl;
    http2 on;
    server_name $DOMAIN;
    server_tokens off;
    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    root $WEB; index index.html;
    location / { try_files \$uri \$uri/ =404; }
}
EOC
  nginx -t -q || die "nginx: битый конфиг"
  systemctl reload nginx
  ok "Self-steal: $DOMAIN → свой сайт на 127.0.0.1:8443"
fi

# ---------- 7. 3x-ui ----------
if [[ -x $XUI_BIN ]]; then 
  info "Обновляю установленный 3x-ui до последней версии…"
  curl -fsSL https://raw.githubusercontent.com/MHSanaei/3x-ui/main/install.sh -o /tmp/xui-install.sh
  XUI_NONINTERACTIVE=1 XUI_SSL_MODE=none bash /tmp/xui-install.sh ${XUI_VERSION:+"$XUI_VERSION"} </dev/null
else
  info "Ставлю 3x-ui ${XUI_VERSION:-latest}…"
  curl -fsSL https://raw.githubusercontent.com/MHSanaei/3x-ui/main/install.sh -o /tmp/xui-install.sh
  XUI_NONINTERACTIVE=1 XUI_SSL_MODE=none bash /tmp/xui-install.sh ${XUI_VERSION:+"$XUI_VERSION"} </dev/null
fi
"$XUI_BIN" setting -listenIP 127.0.0.1 >/dev/null || true
TOKEN=$("$XUI_BIN" setting -getApiToken -tokenName xui-bootstrap 2>/dev/null | awk '/^apiToken:/{print $2}' || true)
[[ -n $TOKEN ]] || die "x-ui не выдал API-токен (убедитесь, что установлена актуальная версия 3x-ui)"
systemctl restart x-ui
SHOW=$("$XUI_BIN" setting -show)
PANEL_PORT=$(awk '$1=="port:"{print $2}' <<<"$SHOW")
WBP=$(awk '$1=="webBasePath:"{print $2}' <<<"$SHOW"); WBP="/${WBP#/}"; WBP="${WBP%/}/"
BASE="http://127.0.0.1:$PANEL_PORT$WBP"
api() { local m=$1 p=$2; shift 2; curl -sS --max-time 180 -X "$m" -H "Authorization: Bearer $TOKEN" "$@" "$BASE$p"; }
for i in $(seq 1 40); do
  if api GET panel/api/server/status 2>/dev/null | jq -e '.success' >/dev/null 2>&1; then break; fi
  (( i < 40 )) || die "API панели не ответило (journalctl -u x-ui)"; sleep 1
done
ok "Панель прибита к 127.0.0.1:$PANEL_PORT, API работает"

if [[ -n $XRAY_VERSION ]]; then
  if api POST "panel/api/server/installXray/$XRAY_VERSION" | jq -e '.success' >/dev/null; then ok "Xray → $XRAY_VERSION"
  else warn "Не поставил Xray $XRAY_VERSION"; fi
fi

# ---------- 8. импорт инбаундов ----------
EXIST=$(api GET panel/api/inbounds/list | jq -r '.obj[]?.port')
TMP=$(mktemp)
cleanup() { rm -f "$TMP"; }
trap cleanup EXIT
for f in "${TEMPLATES[@]}"; do
  n=$(basename "$f")
  render "$f" | jq -c 'del(.id,.nodeId,.originNodeGuid,.fallbackParent) | .up=0 | .down=0
                       | .clientStats = ((.clientStats // []) | map(.up=0 | .down=0))' > "$TMP"
  p=$(jq -r .port "$TMP")
  if grep -qx "$p" <<<"$EXIST"; then warn "$n: порт $p уже занят — пропускаю"; continue; fi
  r=$(api POST panel/api/inbounds/import --data-urlencode "data@$TMP")
  jq -e '.success' >/dev/null <<<"$r" || die "$n: панель отказала: $(jq -r '.msg // .' <<<"$r")"
  ok "$n → порт $p"
done

# ---------- 9. роутинг: RU режем на сервере ----------
if [[ $BLOCK_RU == 1 ]]; then
  api POST panel/api/xray/ | jq -c '(.obj | if type=="string" then (fromjson? // {}) else (. // {}) end) | .xraySetting
    | if any(.routing.rules[]?; (.ip // []) | any(.[]; . == "geoip:ru")) then . else
      .routing.rules = ([.routing.rules[] | select(.outboundTag == "api")]
        + [{"type":"field","outboundTag":"blocked","ip":["geoip:ru"]},
           {"type":"field","outboundTag":"blocked","domain":["geosite:category-ru","domain:ru","domain:su","domain:xn--p1ai"]}]
        + [.routing.rules[] | select(.outboundTag != "api")]) end' > "$TMP" || true
  if [[ -s $TMP ]] && api POST panel/api/xray/update --data-urlencode "xraySetting@$TMP" | jq -e '.success' >/dev/null; then
    ok "Роутинг: трафик к RU режется на сервере"; else warn "Роутинг не обновился"; fi
fi

# ---------- 10. итог ----------
U=""; P=""
if [[ -r /etc/x-ui/install-result.env ]]; then
  U=$(. /etc/x-ui/install-result.env; echo "$XUI_USERNAME"); P=$(. /etc/x-ui/install-result.env; echo "$XUI_PASSWORD")
fi
XRAY_VER=$( { /usr/local/x-ui/bin/xray-linux-* version 2>/dev/null || true; } | awk 'NR==1{print $2}')
LINKS=$(api GET panel/api/inbounds/allLinks -H "Host: $PUBLIC_HOST" 2>/dev/null | jq -r '.obj[]?' || true)
{
  echo "=== $PUBLIC_HOST ($SERVER_IP) — $(date -u '+%F %H:%M') UTC ==="
  echo "Маска: $MASK_MODE | SNI: $SNI | dest: $DEST | Xray: ${XRAY_VER:-?}"
  echo; echo "Панель (только через туннель):"
  echo "  ssh -N -L 2222:127.0.0.1:$PANEL_PORT -p ${SSH_PORTS[0]} root@$SERVER_IP"
  echo "  http://127.0.0.1:2222$WBP   ${U:+логин: $U  пароль: $P}"
  echo; echo "Ссылки:"; echo "${LINKS:-(не получил — возьми в панели)}"
} > "$RESULT"; chmod 600 "$RESULT"; cat "$RESULT"
ok "Готово"
