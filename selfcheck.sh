#!/usr/bin/env bash
# ============================================================================
#  selfcheck.sh — быстрая диагностика сервера xui-bootstrap.
#  Запускать НА VPS от root:   bash selfcheck.sh
#  Ничего не меняет, только читает состояние.
# ============================================================================
set -uo pipefail
G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; Z=$'\033[0m'
ok(){ echo "${G}[ok]${Z} $*"; }; no(){ echo "${R}[!!]${Z} $*"; }; nt(){ echo "${Y}[..]${Z} $*"; }
DB=/etc/x-ui/x-ui.db
XUI=/usr/local/x-ui/x-ui
dbget(){ sqlite3 "$DB" "SELECT value FROM settings WHERE key='$1';" 2>/dev/null || true; }

echo "== Службы =="
MAIN=$(systemctl show -p MainPID --value x-ui 2>/dev/null || echo 0)
if [[ ${MAIN:-0} -gt 0 ]]; then ok "x-ui активен (pid $MAIN)"; else no "x-ui НЕ запущен → systemctl status x-ui"; fi
# xray — дочерний процесс x-ui: `bin/xray-linux-amd64 -c bin/config.json`
if [[ ${MAIN:-0} -gt 0 ]] && pgrep -P "$MAIN" -f xray >/dev/null 2>&1; then ok "ядро xray запущено"
else no "ядро xray НЕ запущено → journalctl -u x-ui -n 50"; fi
# shellcheck disable=SC2211
v=$({ /usr/local/x-ui/bin/xray-linux-* version 2>/dev/null || true; } | awk 'NR==1{print $2}')
echo "   Xray: ${v:-?} | 3x-ui: $("$XUI" -v 2>/dev/null | head -n1 || echo '?')"
r=$(journalctl -u x-ui --since '-24h' --no-pager 2>/dev/null | grep -c 'Started x-ui' || true)
if [[ ${r:-0} -gt 2 ]]; then
  no "x-ui перезапускался ${r} раз за 24 ч — каждый рестарт рвёт подключения клиентов"
  journalctl --since '-24h' --no-pager 2>/dev/null | grep -E 'xui-warp\[|xui-update\[' | grep -iE 'ротир|смен|IP|обнов' | tail -n 3 | sed 's/^/     /'
else
  ok "x-ui перезапусков за 24 ч: ${r:-0}"
fi

echo "== Панель =="
listen=$("$XUI" setting -getListen 2>/dev/null | awk '/listenIP:/{print $2}')
port=$(dbget webPort); cert=$(dbget webCertFile)
scheme=http; [[ -n $cert ]] && scheme=https
if [[ -z $listen || $listen == 0.0.0.0 || $listen == :: ]]; then
  nt "панель открыта наружу: $scheme://<IP>:$port (PANEL_PUBLIC=1)"
  [[ $scheme == http ]] && no "панель наружу по HTTP — пароль идёт открытым текстом"
else
  ok "панель только на $listen:$port ($scheme) — вход через SSH-туннель:"
  echo "     ssh -N -L 2222:127.0.0.1:$port root@<IP>   →   $scheme://127.0.0.1:2222$(dbget webBasePath)"
fi

echo "== Инбаунды (из API панели) =="
LIB=/usr/local/share/xui-bootstrap/lib
LIST=''
if [[ -r $LIB/xui.sh && -r $LIB/common.sh ]]; then
  # shellcheck source=/dev/null
  . "$LIB/common.sh"; . "$LIB/xui.sh"
  if xui_api_connect xui-selfcheck 2>/dev/null; then
    LIST=$(api GET panel/api/inbounds/list 2>/dev/null || true)
  fi
fi
if jq -e '.success' >/dev/null 2>&1 <<<"$LIST"; then
  # для каждого включённого инбаунда: порт, L4, реально ли слушается, устаревшее ли
  jq -r '.obj[]? | select(.enable) |
      ((.streamSettings // "{}") | if type=="string" then (fromjson? // {}) else . end) as $ss |
      [.remark, (.port|tostring), .protocol, ($ss.network // "tcp"), ($ss.security // "none"),
       ($ss.tlsSettings.certificates[0].certificateFile // "-")] | @tsv' <<<"$LIST" |
  while IFS=$'\t' read -r remark port proto net sec cf; do
    case "$proto:$net" in hysteria* | tuic* | wireguard* | amneziawg* | *:kcp | *:hysteria) l4=udp; flag=-Hlun ;; *) l4=tcp; flag=-Hltn ;; esac
    if ss "$flag" "sport = :$port" 2>/dev/null | grep -q .; then st="${G}слушает${Z}"; else st="${R}НЕ слушает${Z}"; fi
    dep=''
    case "$proto" in trojan) dep=' ⚠ Trojan устарел в Xray' ;; shadowsocks) dep=' ⚠ Shadowsocks устарел в Xray' ;; vmess) dep=' ⚠ VMess устарел' ;; esac
    case "$net" in grpc) dep="$dep ⚠ gRPC устарел (замена — XHTTP)" ;; ws | httpupgrade) dep="$dep ⚠ $net устарел (замена — XHTTP)" ;; esac
    [[ $sec == reality && $port != 443 ]] && dep="$dep ⚠ REALITY не на 443"
    # TLS-инбаунд со сертификатом из файла: просрочен → клиенты получают «expired certificate»
    if [[ $cf != - && -r $cf ]] && ! openssl x509 -in "$cf" -noout -checkend 0 >/dev/null 2>&1; then
      dep="$dep ${R}⚠ сертификат ИСТЁК${Z}"
    fi
    printf '   • %-24s %5s/%s  %-11s %-9s %b%s\n' "$remark" "$port" "$l4" "$proto" "$net" "$st" "$dep"
  done
  echo "   Устаревшие функции перестанут работать, когда Xray их удалит. Проверить новое ядро заранее: xui-update check"
else
  no "API панели не отвечает (или нет библиотек xui-bootstrap в $LIB)"
fi

if [[ -r $LIB/xui.sh ]]; then
  n=$(XUI_DB=$DB xui_fix_ocsp --dry-run 2>/dev/null || echo 0)
  if [[ ${n:-0} -gt 0 ]]; then
    nt "ocspStapling ≠ 0 в $n инбаунд(ах) → варнинг «ignoring invalid OCSP» (у Let's Encrypt нет OCSP). Исправить: bash update-tools.sh --fix-ocsp"
  fi
fi

echo "== Удалённые правила маршрутизации подписки (Happ/Clash) =="
any=0
for key in subRoutingRules subJsonRoutingRules subClashRules; do
  url=$(dbget "$key")
  [[ $url == https://* ]] || continue
  any=1
  echo "   $key → $url"
  f=$(mktemp)
  r4=$(curl -4 -sS -o "$f" -w '%{http_code} %{size_download}B %{time_total}s' --max-time 6 -A '3x-ui-remote-routing/1.0' "$url" 2>&1 || true)
  r6=$(curl -6 -sS -o /dev/null -w '%{http_code} %{time_total}s' --max-time 6 "$url" 2>&1 || true)
  echo "     IPv4: $r4 | IPv6: $r6"
  sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
  if [[ $key == subClashRules ]]; then
    [[ $sz -gt 2097152 ]] && no "     $sz Б > лимита Clash 2 МБ — панель отвергнет"
  else
    # лимиты 3x-ui для Happ: тело ≤ 16 КБ, а итоговый deeplink
    # «happ://routing/onadd/» + base64(сжатый JSON) ≤ 8 КБ → JSON ≲ 6 КБ
    val=$(python3 -I - "$f" <<'PY' 2>/dev/null
import base64, json, sys
t = open(sys.argv[1], encoding="utf-8", errors="replace").read().strip()
if t.startswith("{"):
    try:
        c = json.dumps(json.loads(t), separators=(",", ":"), ensure_ascii=False).encode()
        print(len("happ://routing/onadd/") + len(base64.b64encode(c)), len(c))
    except ValueError:
        print("badjson 0")
else:
    print(len(t), 0)
PY
)
    read -r hdr cj <<<"${val:-0 0}"
    if [[ $sz -gt 16384 ]]; then
      no "     ответ $sz Б > 16 КБ — панель отвергает (отсюда «no validated value is cached» каждые 5 мин)"
    elif [[ $hdr == badjson ]]; then
      no "     ответ — невалидный JSON"
    elif [[ ${hdr:-0} -gt 8192 ]]; then
      no "     итоговый deeplink $hdr Б > 8 КБ (сжатый JSON $cj Б, нужно ≲ 6 КБ) — панель отвергает"
    else
      ok "     укладывается в лимиты Happ (deeplink $hdr Б из 8192)"
    fi
  fi
  rm -f "$f"
done
[[ $any == 0 ]] && ok "удалённых источников нет"

echo "== Таймеры =="
systemctl list-timers 'xui-*' --no-pager 2>/dev/null | grep -E 'NEXT|xui-' || nt "таймеры xui-* не найдены"
LEF=/etc/x-ui-bootstrap/le-fullchain.pem
if [[ -s $LEF ]]; then
  end=$(openssl x509 -in "$LEF" -noout -enddate 2>/dev/null | cut -d= -f2)
  if ! openssl x509 -in "$LEF" -noout -checkend 0 >/dev/null 2>&1; then
    no "сертификат LE ИСТЁК ($end) — Hysteria2/TUIC/WS-TLS и обновление подписки не работают. Исправить: bash update-tools.sh"
  elif ! openssl x509 -in "$LEF" -noout -checkend 172800 >/dev/null 2>&1; then
    no "сертификат LE истекает меньше чем через 48 ч ($end) — плановое продление не срабатывает. Исправить: bash update-tools.sh"
  else
    ok "сертификат LE действует до $end"
  fi
  errs=$(journalctl -u xui-acme-renew --since '-8d' --no-pager 2>/dev/null \
         | grep -iE 'error|invalid|timeout|refused|rate.?limit|unauthorized' | tail -n 3 || true)
  [[ -n $errs ]] && { echo "   Ошибки продления за 8 сут:"; sed 's/^/     /' <<<"$errs"; }
  last=$(journalctl -u xui-acme-renew --since '-8d' --no-pager 2>/dev/null | grep -cE 'Cert success|Skipping|Renew' || true)
  echo "   Записей xui-acme-renew за 8 сут: ${last:-0}  (подробно: journalctl -u xui-acme-renew -n 30)"
fi

echo "== WARP =="
if systemctl is-active --quiet warp-svc 2>/dev/null; then
  nt "запущен warp-svc (официальный клиент Cloudflare) — xui-bootstrap его не ставит"
elif ls /etc/apt/sources.list.d/*cloudflare* >/dev/null 2>&1; then
  nt "warp-svc удалён, но репозиторий Cloudflare остался в apt: $(ls /etc/apt/sources.list.d/*cloudflare* | tr '\n' ' ')"
fi
# куда идёт Gemini (routing_state из lib/routing.sh рядом со скриптом)
# shellcheck source=lib/routing.sh
if . "$(dirname "${BASH_SOURCE[0]}")/lib/routing.sh" 2>/dev/null && command -v jq >/dev/null 2>&1; then
  case $(dbget xrayTemplateConfig | routing_state) in
    google-warp)   ok "Gemini и вся сессия Google → WARP, YouTube → напрямую" ;;
    gemini-warp)   if grep -qsE '^WARP_GOOGLE=.?0' "$(dirname "${BASH_SOURCE[0]}")/config.env"; then
                     ok "через WARP только Gemini (WARP_GOOGLE=0)"
                   else
                     no "через WARP только Gemini, вход в Google — с IP VPS → «необычный трафик» в Gemini. Исправить: bash update-tools.sh --routing"
                   fi ;;
    gemini-direct) nt "Gemini идёт напрямую, мимо WARP (WARP не настроен или был недоступен при установке)" ;;
    *)             nt "правила Gemini в шаблоне Xray нет" ;;
  esac
fi
command -v xui-warp >/dev/null 2>&1 && echo "   подробно: xui-warp diag"

echo "== Выходной IP VPS =="
t=$(curl -s --max-time 8 https://1.1.1.1/cdn-cgi/trace 2>/dev/null || true)
echo "   $(awk -F= '$1~/^(ip|colo|warp)$/{printf "%s=%s ", $1, $2}' <<<"$t")"
grep -q '^warp=on' <<<"$t" && no "warp=on: ВЕСЬ трафик сервера идёт через warp-svc (полный туннель)"

echo "== SSH и fail2ban =="
pa=$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2}')
prl=$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2}')
if [[ $pa == no ]]; then ok "вход по паролю выключен"; else no "вход по паролю ВКЛЮЧЁН (passwordauthentication=$pa, permitrootlogin=$prl)"; fi
keys=$(grep -cE '^(ssh-(ed25519|rsa)|ecdsa-sha2-|sk-)' /root/.ssh/authorized_keys 2>/dev/null || true)
echo "   ключей в /root/.ssh/authorized_keys: ${keys:-0}"
if systemctl is-active --quiet fail2ban; then
  b=$(fail2ban-client status sshd 2>/dev/null | awk -F: '/Currently banned/{gsub(/[ \t]/,"",$2); print $2}')
  tb=$(fail2ban-client status sshd 2>/dev/null | awk -F: '/Total banned/{gsub(/[ \t]/,"",$2); print $2}')
  ok "fail2ban: sshd забанено сейчас ${b:-?}, всего ${tb:-?}"
else
  no "fail2ban не активен → systemctl status fail2ban"
fi
nft list table inet xui_ddos >/dev/null 2>&1 && ok "nft-таблица xui_ddos на месте" || nt "nft xui_ddos не найдена"

echo; echo "Готово. Красное [!!] — требует внимания, жёлтое [..] — информационно."
