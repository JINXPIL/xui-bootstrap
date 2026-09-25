#!/usr/bin/env bash
# xui-bootstrap: 3x-ui на чистом VPS + маскировка + твои инбаунды.
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
[[ "${ID:-} ${ID_LIKE:-}" == *debian* ]] || die "Только Debian/Ubuntu (у тебя ${PRETTY_NAME:-?})"
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
"${APT[@]}" install "${PKGS[@]}" >/dev/null

# ---------- 2. IP и параметры маски ----------
SERVER_IP=$(curl -4fsS --max-time 6 https://api.ipify.org || ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}')
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
  sysctl -q --system >/dev/null 2>&1 || warn "sysctl применился не полностью (LXC/OpenVZ?)"
fi

# ---------- 5. SSH, фаервол, fail2ban ----------
mapfile -t SSH_PORTS < <( { sshd -T 2>/dev/null | awk '$1=="port"{print $2}'; [[ -n ${SSH_CONNECTION:-} ]] && echo "${SSH_CONNECTION##* }"; } | sort -un )
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
  a1=$(asn_of "$SERVER_IP"); a2=$(asn_of "$(getent ahostsv4 "$SNI" | awk 'NR==1{print $1}')")
  if [[ -n $a1 && -n $a2 ]]; then
    if [[ $a1 == "$a2" ]]; then ok "Донор в той же AS$a1, что и VPS"
    else warn "Донор в AS$a2, VPS в AS$a1 — лучше донор из подсети/ASN своего хостера"; fi
  fi
fi

if [[ $MASK_MODE == selfsteal ]]; then
  ips=$(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
  [[ " $ips " == *" $SERVER_IP "* ]] || die "$DOMAIN → [${ips:-нет}], а сервер $SERVER_IP. Поправь A-запись (в Cloudflare — серое облако)"
  WEB=/var/www/decoy; mkdir -p "$WEB"
  if [[ -d $DIR/site ]]; then cp -r "$DIR/site/." "$WEB/"
  elif [[ ! -f $WEB/index.html ]]; then
    t=${DOMAIN%%.*}
    cat > "$WEB/index.html" <<EOF
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${t^}</title><style>body{font:16px/1.6 system-ui,sans-serif;max-width:640px;margin:10vh auto;padding:0 20px;color:#222}
footer{margin-top:4em;color:#888;font-size:14px}@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}}</style></head>
<body><h1>${t^}</h1><p>Personal notes, small tools and experiments. The new version of the site is on its way.</p>
<footer>&copy; $(date +%Y) ${DOMAIN}</footer></body></html>
