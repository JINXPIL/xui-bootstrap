#!/usr/bin/env bash
# tests/warp_test.sh — поведенческие тесты WARP-логики на заглушках (без сети).
#   • фейковый xray реально слушает socks-порт и записывает выбранный эндпоинт;
#   • фейковый curl отвечает как Cloudflare trace / Google / API регистрации;
#   • проверяем коды warp_health, решения xui-warp и то, что панель
#     перезапускается (swap) ТОЛЬКО при проверенном улучшении.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v ss >/dev/null && command -v python3 >/dev/null && command -v jq >/dev/null \
  || { echo "warp_test: нужны ss, python3, jq — пропуск"; exit 0; }

T=$(mktemp -d)
cleanup() { pkill -f "$T/bin/xray" 2>/dev/null; pkill -f "xui-warp-fake-listener" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
mkdir -p "$T/bin" "$T/lib" "$T/state" "$T/etc"
export FAKE_STATE="$T/state" WARP_ENV="$T/etc/warp.env"
fail=0
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '\033[31mFAIL\033[0m %s\n' "$*"; fail=1; }

# --- заглушки ---------------------------------------------------------------
cat >"$T/bin/xray" <<'EOF'
#!/usr/bin/env bash
[[ ${1:-} == run ]] || exit 0
cfg=$3
[[ ${FAKE_XRAY_FAIL:-0} == 1 ]] && { echo "Failed to start: fake" >&2; exit 23; }
jq -r '.outbounds[0].settings.peers[0].endpoint // "socks"' "$cfg" >"$FAKE_STATE/ep"
port=$(jq -r '.inbounds[0].port' "$cfg")
exec python3 -c 'import socket,sys,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("127.0.0.1",int(sys.argv[1]))); s.listen(8); time.sleep(120)' "$port" xui-warp-fake-listener
EOF
cat >"$T/bin/curl" <<'EOF'
#!/usr/bin/env bash
url=''; wfmt=''; prev=''
for a in "$@"; do [[ $prev == -w ]] && wfmt=$a; [[ $a == http*://* ]] && url=$a; prev=$a; done
ep=$(cat "$FAKE_STATE/ep" 2>/dev/null || true)
ok=0
[[ ${FAKE_TUNNEL:-on} == on ]] && ok=1
[[ -n ${FAKE_GOOD_EP:-} && $ep == "$FAKE_GOOD_EP" ]] && ok=1
case $url in
  */reg)
    n=$(( $(cat "$FAKE_STATE/regs" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$FAKE_STATE/regs"
    printf '{"config":{"client_id":"AQID","peers":[{"public_key":"PUB%s","endpoint":{"v4":"162.159.192.%s:0","host":"engage.cloudflareclient.com:2408"}}],"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110::2"}}}}' "$n" "$n"
    exit 0 ;;
  *cdn-cgi/trace)
    [[ $ok == 1 ]] && { printf 'fl=1\nip=104.28.1.7\ncolo=FRA\nwarp=on\n'; exit 0; }
    exit 28 ;;
  *googleapis*)
    if [[ $ok != 1 ]]; then [[ -n $wfmt ]] && printf 000; exit 28; fi
    code=${FAKE_GOOGLE:-404}
    [[ -n ${FAKE_GOOGLE_OK_EP:-} && $ep == "$FAKE_GOOGLE_OK_EP" ]] && code=404
    [[ -n $wfmt ]] && printf '%s' "$code"
    [[ $code == 000 ]] && exit 28
    exit 0 ;;
esac
exit 0
EOF
cat >"$T/bin/wg" <<'EOF'
#!/usr/bin/env bash
case $1 in genkey) echo "PRIV$RANDOM$RANDOM=" ;; pubkey) read -r k; echo "PUB${k}" ;; esac
EOF
cat >"$T/bin/sleep" <<'EOF'
#!/usr/bin/env bash
[[ ${1:-} == 0.5 ]] && exec /bin/sleep 0.1
exit 0
EOF
cat >"$T/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$T"/bin/*
export PATH="$T/bin:$PATH"

cp "$ROOT/lib/common.sh" "$ROOT/lib/keys.sh" "$ROOT/lib/warp.sh" "$T/lib/"
cat >"$T/lib/xui.sh" <<'EOF'
XUI_BIN=/bin/true
xui_assets_install() { :; }
xray_tmpl_get_or_default() { echo '{"outbounds":[{"tag":"direct","protocol":"freedom"}]}'; }
xray_tmpl_set() { cp "$1" "$FAKE_STATE/tmpl.json"; echo x >>"$FAKE_STATE/swaps"; }
EOF
sed "s#^LIB=.*#LIB=$T/lib#" "$ROOT/bin/xui-warp" >"$T/xui-warp"

L() { ( . "$T/lib/common.sh"; . "$T/lib/keys.sh"; . "$T/lib/xui.sh"; . "$T/lib/warp.sh"; "$@" ); }
reset_state() { rm -f "$FAKE_STATE"/* "$WARP_ENV"; }
swaps() { [[ -f $FAKE_STATE/swaps ]] && wc -l <"$FAKE_STATE/swaps" | tr -d ' ' || echo 0; }

echo "== регистрация и outbound =="
reset_state
L warp_register 2>/dev/null
[[ $(grep '^WARP_ENDPOINT=' "$WARP_ENV") == "WARP_ENDPOINT=162.159.192.1:2408" ]] \
  && pass "эндпоинт сохранён IP-литералом (без зависимости от DNS)" || bad "эндпоинт: $(grep WARP_ENDPOINT "$WARP_ENV")"
[[ $(stat -c %a "$WARP_ENV") == 600 ]] && pass "warp.env с правами 600" || bad "права warp.env: $(stat -c %a "$WARP_ENV")"
ob=$(L warp_outbound_json 2>/dev/null)
jq -e '.protocol=="wireguard" and .settings.mtu==1280 and (.settings|has("domainStrategy")|not) and .settings.peers[0].endpoint=="162.159.192.1:2408"' >/dev/null <<<"$ob" \
  && pass "wireguard-outbound: mtu 1280, без устаревшего domainStrategy" || bad "outbound: $ob"
ob=$(WARP_ENDPOINT_OVERRIDE=162.159.192.1:500 L warp_outbound_json 2>/dev/null)
[[ $(jq -r '.settings.peers[0].endpoint' <<<"$ob") == 162.159.192.1:500 ]] && pass "WARP_ENDPOINT_OVERRIDE подменяет эндпоинт" || bad "override не сработал"
L warp_env_set WARP_SOCKS 127.0.0.1:40000
ob=$(L warp_outbound_json 2>/dev/null)
jq -e '.protocol=="socks" and .settings.address=="127.0.0.1" and .settings.port==40000' >/dev/null <<<"$ob" \
  && pass "режим warp-svc: socks-outbound в актуальном формате Xray" || bad "socks outbound: $ob"
L warp_env_del WARP_SOCKS
grep -q '^WARP_SOCKS=' "$WARP_ENV" && bad "WARP_SOCKS не удалён" || pass "warp_env_del убирает ключ, остальное цело ($(wc -l <"$WARP_ENV") строк)"

echo "== warp_health: коды возврата =="
hc() { local rc=0; L warp_health >/dev/null 2>&1 || rc=$?; echo "$rc"; }
[[ $(FAKE_TUNNEL=on FAKE_GOOGLE=404 hc) == 0 ]] && pass "туннель жив + Google 404 → 0" || bad "ожидал 0"
[[ $(FAKE_TUNNEL=on FAKE_GOOGLE=000 hc) == 1 ]] && pass "туннель жив + Google молчит → 1" || bad "ожидал 1"
d=$(FAKE_TUNNEL=on FAKE_GOOGLE=000 L bash -c '. '"$T"'/lib/common.sh; . '"$T"'/lib/keys.sh; . '"$T"'/lib/xui.sh; . '"$T"'/lib/warp.sh; warp_health >/dev/null 2>&1; echo "$WARP_HEALTH_DETAIL"')
[[ $d == "google=000" ]] && pass "код без задвоения: «$d» (раньше было 000000)" || bad "detail: «$d»"
[[ $(FAKE_TUNNEL=off hc) == 3 ]] && pass "туннель мёртв → 3 (смена IP бесполезна)" || bad "ожидал 3"
[[ $(FAKE_XRAY_FAIL=1 hc) == 2 ]] && pass "xray не стартовал → 2 (проверить нельзя)" || bad "ожидал 2"

echo "== xui-warp health: решения =="
run_warp() { bash "$T/xui-warp" "$@" 2>&1; }
reset_state; L warp_register 2>/dev/null; rm -f "$FAKE_STATE/regs"
out=$(FAKE_TUNNEL=on FAKE_GOOGLE=404 run_warp health); rc=$?
[[ $rc == 0 && $(swaps) == 0 ]] && pass "здоров → без изменений и без рестарта" || bad "здоров: rc=$rc swaps=$(swaps)"

out=$(FAKE_TUNNEL=off run_warp health); rc=$?
[[ $rc == 1 && $(swaps) == 0 && $out == *"НЕ перезапускаю"* ]] && pass "туннель мёртв везде → панель НЕ трогаем" || bad "мёртвый туннель: rc=$rc swaps=$(swaps)"
[[ ! -f $FAKE_STATE/regs ]] && pass "…и бессмысленных перерегистраций нет" || bad "лишние регистрации: $(cat "$FAKE_STATE/regs")"

out=$(FAKE_TUNNEL=off FAKE_GOOD_EP=162.159.192.1:500 run_warp health); rc=$?
[[ $rc == 0 && $(swaps) == 1 && $(grep '^WARP_ENDPOINT=' "$WARP_ENV") == "WARP_ENDPOINT=162.159.192.1:500" ]] \
  && pass "UDP 2408 закрыт, 500 открыт → переключился на :500 (1 рестарт)" || bad "подбор порта: rc=$rc swaps=$(swaps) $(grep WARP_ENDPOINT "$WARP_ENV")"

reset_state; L warp_register 2>/dev/null; rm -f "$FAKE_STATE/regs"
before=$(grep '^WARP_PRIV=' "$WARP_ENV")
out=$(FAKE_TUNNEL=on FAKE_GOOGLE=403 run_warp health); rc=$?
[[ $rc == 1 && $(swaps) == 0 && $(grep '^WARP_PRIV=' "$WARP_ENV") == "$before" ]] \
  && pass "Google блокирует, кандидаты тоже плохие → рабочий конфиг цел, без рестарта" || bad "плохие кандидаты: rc=$rc swaps=$(swaps)"

reset_state; L warp_register 2>/dev/null; echo 1 >"$FAKE_STATE/regs"
before=$(grep '^WARP_PRIV=' "$WARP_ENV")
out=$(FAKE_TUNNEL=on FAKE_GOOGLE=403 FAKE_GOOGLE_OK_EP=162.159.192.2:2408 run_warp health); rc=$?
[[ $rc == 0 && $(swaps) == 1 && $(grep '^WARP_PRIV=' "$WARP_ENV") != "$before" ]] \
  && pass "Google блокирует, кандидат здоров → заменён проверенным (1 рестарт)" || bad "здоровый кандидат: rc=$rc swaps=$(swaps)"
jq -e '.outbounds[]|select(.tag=="warp")|.settings.peers[0].endpoint=="162.159.192.2:2408"' >/dev/null "$FAKE_STATE/tmpl.json" 2>/dev/null \
  && pass "в шаблон панели попал именно проверенный кандидат" || bad "в шаблоне не тот outbound"
if compgen -G "$T/etc/.warp.*" >/dev/null; then bad "остались временные файлы кандидатов"; else pass "временных файлов кандидатов не осталось"; fi

echo "== use-svc / use-wg =="
reset_state; L warp_register 2>/dev/null
out=$(FAKE_TUNNEL=off run_warp use-svc 40000); rc=$?
[[ $rc != 0 && $(swaps) == 0 ]] && ! grep -q '^WARP_SOCKS=' "$WARP_ENV" && pass "use-svc без живого прокси → отказ, ничего не меняет" || bad "use-svc без прокси: rc=$rc"
out=$(FAKE_TUNNEL=on run_warp use-svc 40000); rc=$?
[[ $rc == 0 && $(swaps) == 1 ]] && grep -q '^WARP_SOCKS=127.0.0.1:40000' "$WARP_ENV" && pass "use-svc с живым warp-svc → переключено" || bad "use-svc: rc=$rc"
out=$(FAKE_TUNNEL=on FAKE_GOOGLE=403 run_warp health); rc=$?
[[ $(swaps) == 1 && $out == *"warp-svc"* ]] && pass "в режиме warp-svc health не ротирует чужую регистрацию" || bad "health в режиме svc: swaps=$(swaps)"
out=$(run_warp use-wg); rc=$?
[[ $rc == 0 ]] && ! grep -q '^WARP_SOCKS=' "$WARP_ENV" && pass "use-wg возвращает встроенный WireGuard" || bad "use-wg: rc=$rc"

echo
[[ $fail == 0 ]] && { echo "WARP: ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ"; exit 0; } || { echo "WARP: ЕСТЬ ОШИБКИ"; exit 1; }
