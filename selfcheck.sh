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
dbget(){ sqlite3 "$DB" "SELECT value FROM settings WHERE key='$1';" 2>/dev/null || true; }

echo "== Службы =="
systemctl is-active --quiet x-ui && ok "x-ui активен" || no "x-ui НЕ запущен → systemctl status x-ui"
# имя процесса ядра — xray-linux-amd64 (ядро урезает его до 15 символов),
# поэтому ищем по полной командной строке, а не по имени
pgrep -f '/usr/local/x-ui/bin/xray' >/dev/null 2>&1 && ok "процесс xray жив" || no "xray НЕ запущен → journalctl -u x-ui -n 50"
# shellcheck disable=SC2211
v=$({ /usr/local/x-ui/bin/xray-linux-* version 2>/dev/null || true; } | awk 'NR==1{print $2}')
echo "   Xray версия: ${v:-?}"
r=$(journalctl -u x-ui --since '-24h' --no-pager 2>/dev/null | grep -c 'Started x-ui' || true)
if [[ ${r:-0} -gt 2 ]]; then
  no "x-ui перезапускался ${r} раз за 24 ч — каждый рестарт рвёт ВСЕ подключения клиентов"
  journalctl --since '-24h' --no-pager 2>/dev/null | grep -E 'xui-warp\[|xui-update\[' | grep -iE 'ротир|смен|IP|обнов' | tail -n 3 | sed 's/^/     /'
else
  ok "x-ui перезапусков за 24 ч: ${r:-0}"
fi

echo "== Порты (слушатели) =="
for p in 443 2053 8443; do
  ss -Hltn "sport = :$p" 2>/dev/null | grep -q . && ok "TCP $p слушается" || nt "TCP $p не слушается (норм, если протокол выключен)"
done
ss -Hlun 'sport = :443' 2>/dev/null | grep -q . && ok "UDP 443 слушается (Hysteria2)" || nt "UDP 443 не слушается"

echo "== Инбаунды (через API панели) =="
LIB=/usr/local/share/xui-bootstrap/lib
if [[ -r $LIB/xui.sh && -r $LIB/common.sh ]]; then
  # shellcheck source=/dev/null
  . "$LIB/common.sh"; . "$LIB/xui.sh"
  if xui_api_connect xui-selfcheck 2>/dev/null; then
    n=$(api GET panel/api/inbounds/list 2>/dev/null | jq '[.obj[]?]|length' 2>/dev/null || echo '?')
    ok "API отвечает, инбаундов: $n"
    api GET panel/api/inbounds/list 2>/dev/null \
      | jq -r '.obj[]? | "   • \(.remark // .tag // "?")  порт \(.port)/\(.protocol)  \(if .enable then "вкл" else "ВЫКЛ" end)"' 2>/dev/null || true
  else
    no "API панели не отвечает (панель поднята? x-ui активен?)"
  fi
else
  nt "библиотеки xui-bootstrap не найдены в $LIB — пропускаю проверку API"
fi

echo "== Удалённые правила маршрутизации подписки (Happ/Clash) =="
for key in subRoutingRules subClashRules subJsonRoutingRules; do
  url=$(dbget "$key")
  [[ $url == https://* ]] || continue
  echo "   $key → $url"
  # тот же бюджет, что у панели: 6 с на всё
  r4=$(curl -4 -sS -o /tmp/.xui-sc-route -w '%{http_code} %{size_download}B %{time_total}s' --max-time 6 -A '3x-ui-remote-routing/1.0' "$url" 2>&1 || true)
  r6=$(curl -6 -sS -o /dev/null -w '%{http_code} %{time_total}s' --max-time 6 "$url" 2>&1 || true)
  echo "     IPv4: $r4"; echo "     IPv6: $r6"
  head -c 60 /tmp/.xui-sc-route 2>/dev/null | tr -d '\n' | sed 's/^/     начало ответа: /'; echo
  sz=$(stat -c %s /tmp/.xui-sc-route 2>/dev/null || echo 0)
  [[ $key != subClashRules && $sz -gt 16384 ]] && no "     ответ $sz Б > лимита Happ 16 КБ — панель его отвергнет"
  rm -f /tmp/.xui-sc-route
done

echo "== Таймеры авто-обновления и WARP =="
if systemctl list-timers 'xui-*' --no-pager 2>/dev/null | grep -qE 'xui-'; then
  systemctl list-timers 'xui-*' --no-pager 2>/dev/null | grep -E 'NEXT|xui-'
else
  nt "таймеры xui-* не найдены"
fi

echo "== WARP =="
if systemctl is-active --quiet warp-svc 2>/dev/null; then
  nt "установлен и запущен warp-svc (официальный клиент Cloudflare) — xui-bootstrap его НЕ ставит и сам не использует"
  echo "     DNS хоста: $(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null | paste -sd' ' -)"
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
if systemctl is-active --quiet fail2ban; then
  b=$(fail2ban-client status sshd 2>/dev/null | awk -F: '/Currently banned/{gsub(/ /,"",$2); print $2}')
  t=$(fail2ban-client status sshd 2>/dev/null | awk -F: '/Total banned/{gsub(/ /,"",$2); print $2}')
  ok "fail2ban: sshd забанено сейчас ${b:-?}, всего ${t:-?}"
else
  no "fail2ban не активен → systemctl status fail2ban"
fi
nft list table inet xui_ddos >/dev/null 2>&1 && ok "nft-таблица xui_ddos на месте" || nt "nft xui_ddos не найдена"

echo; echo "Готово. Красное [!!] — требует внимания, жёлтое [..] — информационно."
