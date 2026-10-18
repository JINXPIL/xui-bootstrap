#!/usr/bin/env bash
# tests/xray_test.sh — проверка шаблонов НАСТОЯЩИМ ядром Xray (`xray run -test`).
#   • все шаблоны инбаундов + наши outbound'ы (direct, WARP WireGuard, WARP socks)
#     должны загружаться;
#   • дефолтный набор (AUTO_INBOUNDS из config.example.env) — без единого
#     предупреждения об устаревших функциях и без REALITY вне 443.
# Бинарник: $XRAY_BIN, `xray` из PATH, либо скачивается при XRAY_DOWNLOAD=1
# (версия — $XRAY_VERSION или последний релиз). Без бинарника — пропуск.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '\033[31mFAIL\033[0m %s\n' "$*"; fail=1; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"

XB=${XRAY_BIN:-$(command -v xray || true)}
if [[ -z $XB && ${XRAY_DOWNLOAD:-0} == 1 ]]; then
  tag=${XRAY_VERSION:-$(git ls-remote --tags --refs https://github.com/XTLS/Xray-core.git 2>/dev/null \
        | awk -F/ '{print $NF}' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1)}
  curl -fsSL -o "$T/x.zip" "https://github.com/XTLS/Xray-core/releases/download/$tag/Xray-linux-64.zip" \
    && python3 -I -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extract("xray", sys.argv[2])' "$T/x.zip" "$T/bin" \
    && chmod +x "$T/bin/xray" && XB="$T/bin/xray"
fi
[[ -n $XB && -x $XB ]] || { echo "xray_test: бинарника xray нет (XRAY_BIN / XRAY_DOWNLOAD=1) — пропуск"; exit 0; }
XB=$(realpath "$XB")   # относительный путь сломал бы симлинк в $T/bin
[[ $XB == "$T/bin/xray" ]] || ln -sf "$XB" "$T/bin/xray"
echo "Ядро: $("$XB" version | head -n1)"

openssl ecparam -genkey -name prime256v1 -out "$T/c.key" 2>/dev/null
openssl req -new -x509 -key "$T/c.key" -out "$T/c.pem" -days 7 -subj /CN=203.0.113.7 -addext subjectAltName=IP:203.0.113.7 2>/dev/null

# рендер каждого шаблона настоящими ключами (gen_x25519 → xray x25519)
render() {
  PATH="$T/bin:$PATH" bash -c '
    set -Eeuo pipefail; cd "$1"; . lib/common.sh; . lib/keys.sh; . lib/inbounds.sh
    gen_ss_key(){ openssl rand -base64 16; }
    LE_OK=1; LE_CERT=$2/c.pem; LE_KEY=$2/c.key; LE_SNI=203.0.113.7
    SNI=vk.com; DEST=vk.com:443; PUBLIC_HOST=203.0.113.7; ss(){ return 0; }
    for k in $3; do
      _render "$k" "inbounds/${TEMPLATE_MAP[$k]}" | jq -c --arg t "in-$k" "{tag:\$t,listen,port,protocol,settings,streamSettings,sniffing}"
    done' _ "$ROOT" "$T" "$1"
}
cat >"$T/warp.env" <<'EOF'
WARP_PRIV=0O1gYkXwqmOQb2MYa6+r3aDsMPGjNsY1M3WLE3YSkUw=
WARP_PEER_PUB=bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
WARP_ENDPOINT=162.159.192.1:2408
WARP_V4=172.16.0.2
WARP_V6=2606:4700:110::2
WARP_RESERVED=1,2,3
EOF
WG=$(WARP_ENV="$T/warp.env" bash -c ". '$ROOT/lib/common.sh'; . '$ROOT/lib/keys.sh'; . '$ROOT/lib/warp.sh'; warp_outbound_json")
# direct — в том виде, в каком его добавляет lib/routing.sh
DIRECT=$(grep -oE '\{tag:"direct", protocol:"freedom"[^]]*\}' "$ROOT/lib/routing.sh" | head -n1)
jq -cen "$DIRECT" >/dev/null 2>&1 || { bad "не разобрал direct-outbound из lib/routing.sh"; DIRECT='{tag:"direct",protocol:"freedom"}'; }
mkcfg() { jq -s --argjson wg "$WG" --argjson d "$(jq -cn "$DIRECT")" '{log:{loglevel:"warning"}, inbounds:., outbounds:[
            $d, {tag:"blocked",protocol:"blackhole",settings:{}}, $wg,
            {tag:"warp-svc",protocol:"socks",settings:{address:"127.0.0.1",port:40000}} ]}'; }
xtest() { local out='' _; for _ in 1 2 3; do out+=$'\n'$("$XB" run -test -c "$1" 2>&1); done; printf '%s' "$out"; }

# tuic не входит: его обслуживает сайдкар tuic-server панели, а не Xray
ALL="xhttp-reality hysteria2 grpc-reality reality-vision trojan-reality ss2022 ws-tls"
render "$ALL" >"$T/all.jsonl" 2>"$T/render.err" || { bad "рендер шаблонов: $(tail -n 3 "$T/render.err")"; }
mkcfg <"$T/all.jsonl" >"$T/all.json"
out=$(xtest "$T/all.json")
nall=$(wc -l <"$T/all.jsonl"); nwant=$(wc -w <<<"$ALL")
if [[ $nall -ne $nwant ]]; then bad "отрендерено $nall инбаундов из $nwant — проверка без них ничего не доказывает"
elif [[ $out == *"Configuration OK"* ]]; then pass "все шаблоны + outbound'ы загружаются ($nall инбаундов)"
else bad "полный конфиг не загружается: $(grep -m1 'Failed' <<<"$out")"; fi

DEF=$(sed -n 's/^AUTO_INBOUNDS="\(.*\)"/\1/p' "$ROOT/config.example.env")
render "$DEF" >"$T/default.jsonl" 2>/dev/null; mkcfg <"$T/default.jsonl" >"$T/default.json"
out=$(xtest "$T/default.json")
if [[ $(wc -l <"$T/default.jsonl") -ne $(wc -w <<<"$DEF") ]]; then
  bad "дефолтный набор отрендерен не полностью ($(wc -l <"$T/default.jsonl") из $(wc -w <<<"$DEF"))"
elif [[ $out != *"Configuration OK"* ]]; then
  # без загрузки остальные проверки дефолта бессмысленны — не засчитываем их
  bad "дефолтный набор не загружается: $(grep -m1 'Failed' <<<"$out")"
else
  pass "дефолтный набор ($DEF) загружается"
  if grep -qE 'deprecated|will be removed|has been removed' <<<"$out"; then
    bad "в дефолтном наборе есть устаревшее: $(grep -oE '(The feature [^(]*|freedom.domainStrategy)' <<<"$out" | sort -u | tr '\n' ';')"
  else pass "дефолтный набор без устаревших функций Xray"; fi
  grep -q 'REALITY: Listening on non-443' <<<"$out" && bad "в дефолте REALITY не на 443" || pass "в дефолте REALITY только на 443"
  grep -q 'freedom.domainStrategy' <<<"$out" && bad "direct использует устаревший freedom.domainStrategy" || pass "direct без устаревшего freedom.domainStrategy"
fi

# временный конфиг проверки WARP: имя как в lib/warp.sh, ядро должно определить формат
cfg=$(mktemp --suffix=.json "$T/xui-warp-XXXXXX"); jq -cn --argjson wg "$WG" '{outbounds:[$wg]}' >"$cfg"
"$XB" run -test -c "$cfg" 2>&1 | grep -q 'Configuration OK' && pass "временный конфиг WARP (*.json) принимается ядром" || bad "временный конфиг WARP не принят"

echo
[[ $fail == 0 ]] && { echo "XRAY: ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ"; exit 0; } || { echo "XRAY: ЕСТЬ ОШИБКИ"; exit 1; }
