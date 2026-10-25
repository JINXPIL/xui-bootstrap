#!/usr/bin/env bash
# tests/idempotency_test.sh — повторный запуск на сервере с уже существующей
# панелью: существующие инбаунды пропускаются, «Duplicate email» не роняет
# bootstrap, порты чужих процессов не освобождаются убийством.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v jq >/dev/null || { echo "idempotency_test: нужен jq — пропуск"; exit 0; }
fail=0
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '\033[31mFAIL\033[0m %s\n' "$*"; fail=1; }
T=$(mktemp -d); trap 'pkill -KILL -f "$T/" 2>/dev/null; rm -rf "$T"' EXIT

cat >"$T/run.sh" <<'EOF'
set -Eeuo pipefail
cd "$1"
. lib/common.sh; . lib/keys.sh; . lib/inbounds.sh
gen_uuid(){ echo 11111111-1111-1111-1111-111111111111; }; gen_x25519(){ echo "P U"; }
gen_shortid(){ printf 0123abcd; }; gen_password(){ echo pw; }; gen_ss_key(){ echo AAAA; }
_ensure_tls_cert(){ CERT_PUB=/c.pem; CERT_KEY=/c.key; CERT_PIN=X; CERT_TRUSTED=1; CERT_SNI=1.2.3.4; }
SNI=vk.com; DEST=vk.com:443; PUBLIC_HOST=1.2.3.4; IMPORT_DELAY=0
api(){ case "$2" in
  panel/api/inbounds/list) printf '%s' "$FAKE_LIST" ;;
  panel/api/inbounds/import) echo x >>"$IMPORTS"; { cat "${4#data@}"; echo; } >>"$IMPORTS.json"; printf '%s' "$FAKE_IMPORT" ;;
  esac; }
ss(){ return 0; }
AUTO_INBOUNDS="${T_SET:-xhttp-reality hysteria2}"; LE_OK=${T_LE:-0}; MASK_MODE=${T_MASK:-reality}
inbounds_provision "$1/inbounds"
echo "TCP=${INB_TCP_PORTS[*]} UDP=${INB_UDP_PORTS[*]}"
EOF

mk() { jq -cn --arg r "$1" --argjson p "$2" --arg pr "$3" --arg e "$4" --arg n "$5" \
  '{remark:$r,port:$p,protocol:$pr,enable:true,
    settings:({clients:[{email:$e}]}|tojson), streamSettings:({network:$n}|tojson), clientStats:[{email:$e}]}'; }
# состояние сервера пользователя (selfcheck, 3x-ui 3.9.0)
USER_LIST=$(jq -cn \
  --argjson a "$(mk VLESS-Reality-Vision 443 vless reality-vision tcp)" --argjson b "$(mk VLESS-XHTTP-Reality 2053 vless xhttp-reality xhttp)" \
  --argjson c "$(mk VLESS-gRPC-Reality 2087 vless grpc-reality grpc)" --argjson d "$(mk Trojan-Reality 2083 trojan trojan-reality tcp)" \
  --argjson e "$(mk Shadowsocks-2022 2095 shadowsocks ss2022 tcp)"    --argjson f "$(mk Hysteria2 20605 hysteria hysteria2 hysteria)" \
  '{success:true,obj:[$a,$b,$c,$d,$e,$f]}')
EMPTY='{"success":true,"obj":[]}'
run() { export FAKE_LIST=$1 FAKE_IMPORT=$2 IMPORTS="$T/imports"; : >"$IMPORTS"; : >"$IMPORTS.json"
        LC_ALL=C.UTF-8 bash "$T/run.sh" "$ROOT" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
imports() { wc -l <"$T/imports" | tr -d ' '; }

out=$(run "$USER_LIST" '{"success":true}')
[[ $out == *"добавлено 0, уже были 2"* && $(imports) == 0 ]] && pass "сервер пользователя: xhttp и hysteria2 уже есть → пропущены, импорта нет" || bad "существующие не пропущены: $out"
[[ $out != *"порт"*"занят"* ]] && pass "порты существующих инбаундов не «переносятся»" || bad "лишний перенос порта"
[[ $out == *"TCP="*2087*" UDP="*20605* ]] && pass "порты существующих учтены по L4 (gRPC 2087/tcp, Hysteria2 20605/udp) — для фаервола" || bad "порты по L4: $(grep -o 'TCP=.*' <<<"$out")"

out=$(run "$EMPTY" '{"success":true}')
[[ $out == *"добавлено 2, уже были 0"* && $(imports) == 2 ]] && pass "чистая панель → оба импортированы" || bad "чистая панель: $out"
[[ $out == *"xhttp-reality → порт 443"* && $out == *"hysteria2 → порт 443"* ]] && pass "XHTTP 443/tcp и Hysteria2 443/udp на одном порту" || bad "порты дефолта: $out"

out=$(run "$EMPTY" '{"success":false,"msg":"Something went wrong (Duplicate email: xhttp-reality\n)"}')
[[ $out == *"уже были 2"* && $out != *"[xx]"* && $(imports) == 2 ]] && pass "осиротевший клиент (Duplicate email) → пропуск без падения, без повторов" || bad "Duplicate email: imports=$(imports) $out"

out=$(run "$EMPTY" '{"success":false,"msg":"bad config"}')
[[ $out == *"[xx] Не импортировано ни одного инбаунда"* ]] && pass "реальная ошибка импорта по-прежнему останавливает bootstrap" || bad "ошибка импорта проглочена: $out"

# WebSocket: ставится и без домена, если есть доверенный Let's Encrypt на IP
out=$(T_SET=ws-tls T_LE=1 run "$EMPTY" '{"success":true}')
[[ $(imports) == 1 ]] && pass "ws-tls с LE-сертификатом на IP (режим reality) — импортирован" || bad "ws-tls с LE не импортирован: $out"
ws=$(head -n1 "$T/imports.json")
[[ $(jq -c '.streamSettings | fromjson? // . | [.network, .security, .tlsSettings.alpn, .wsSettings.host]' <<<"$ws") == '["ws","tls",["http/1.1"],"1.2.3.4"]' ]] \
  && pass "ws-tls: TLS, ALPN только http/1.1 (иначе клиент договорится на h2 и WebSocket не поднимется), Host = IP серта" \
  || bad "ws-tls: $(jq -c '.streamSettings | fromjson? // . | [.network, .security, .tlsSettings.alpn, .wsSettings.host]' <<<"$ws")"
out=$(T_SET=ws-tls T_LE=0 run "$EMPTY" '{"success":true}')
[[ $(imports) == 0 && $out == *"ws-tls: нужен доверенный сертификат"* ]] && pass "ws-tls без доверенного серта — пропущен с понятной причиной" || bad "ws-tls без LE: imports=$(imports) $out"

# _free_stale_ports: чужой процесс на порту не трогаем, свой осиротевший — снимаем
if command -v ss >/dev/null && command -v python3 >/dev/null; then
  lis() { python3 -c 'import socket,sys,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(1); time.sleep(60)' "$@" & }
  lis 59731 "$T/other-xray-panel" ; P1=$!
  lis 59732 "$T/xui-warp-AbC123.json" ; P2=$!
  sleep 0.5
  bash -c ". '$ROOT/lib/common.sh'; . '$ROOT/lib/inbounds.sh'; _free_stale_ports 59731 59732" 2>/dev/null
  sleep 0.3
  kill -0 "$P1" 2>/dev/null && pass "чужой процесс на порту (напр. xray панели) не убит" || bad "_free_stale_ports убил чужой процесс"
  kill -0 "$P2" 2>/dev/null && bad "осиротевший xray проверки WARP не снят" || pass "осиротевший xray проверки WARP снят"
  { kill -KILL "$P1" "$P2"; wait "$P1" "$P2"; } 2>/dev/null
fi

echo
[[ $fail == 0 ]] && { echo "IDEMPOTENCY: ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ"; exit 0; } || { echo "IDEMPOTENCY: ЕСТЬ ОШИБКИ"; exit 1; }
