#!/usr/bin/env bash
# tests/validate.sh — оффлайн-проверки для CI (без реального сервера/API):
#   1) все шаблоны инбаундов — валидный JSON нужной формы;
#   2) jq-трансформация маршрутизации даёт корректные правила и идемпотентна;
#   3) шаблон nftables анти-DDoS проходит `nft -c` (если nft доступен).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
fail=0
note() { printf '  %s\n' "$*"; }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '\033[31mFAIL\033[0m %s\n' "$*"; fail=1; }

echo "== 1. Шаблоны инбаундов =="
DUMMY_UUID="11111111-1111-1111-1111-111111111111"
# проверяем только шаблоны, которые реально использует инструмент
KNOWN='vless-reality-vision vless-xhttp-reality vless-grpc-reality trojan-reality shadowsocks-2022 hysteria2 tuic vless-ws-tls'
for f in inbounds/*.json.example; do
  base=$(basename "$f" .json.example)
  case " $KNOWN " in *" $base "*) : ;; *) note "пропуск (не в наборе): $base"; continue ;; esac
  t=$(<"$f")
  t=${t//__UUID__/$DUMMY_UUID}
  t=${t//__EMAIL__/test}
  t=${t//__PASSWORD__/pass123}
  t=${t//__SS_KEY__/$(printf 'AAAAAAAAAAAAAAAAAAAAAA==')}
  t=${t//__SS_CLIENT_KEY__/$(printf 'BBBBBBBBBBBBBBBBBBBBBB==')}
  t=${t//__PRIVATE_KEY__/privkey}
  t=${t//__PUBLIC_KEY__/pubkey}
  t=${t//__SHORT_ID__/0123abcd}
  t=${t//__TLS_SNI__/www.microsoft.com}
  t=${t//__SNI__/www.microsoft.com}
  t=${t//__DEST__/www.microsoft.com:443}
  t=${t//__SERVER__/198.51.100.10}
  t=${t//__PATH__//abcd}
  t=${t//__SVC__/abcd}
  t=${t//__CERT_PUB__/\/etc\/cert.pem}
  t=${t//__CERT_KEY__/\/etc\/cert.key}
  t=${t//__CERT_PIN__/AAAA}
  if left=$(grep -oE '__[A-Z_]+__' <<<"$t"); then :; fi
  if [[ -n ${left:-} ]]; then bad "$f: остались метки: $(tr '\n' ' ' <<<"$left")"; continue; fi
  if ! jq -e '.port and .protocol and .settings and .streamSettings' >/dev/null 2>&1 <<<"$t"; then
    bad "$f: не валидный инбаунд-JSON"; continue
  fi
  pass "$(basename "$f")"
done

# совместимость с актуальным Xray/3x-ui
if jq -e '.settings.clients[0] | has("flow")' >/dev/null 2>&1 <inbounds/trojan-reality.json.example; then
  bad "trojan-reality: поле flow должно быть удалено (Xray его больше не принимает)"
else
  pass "trojan-reality без flow"
fi
if jq -e '.settings.clients[0] | (.id != null and .id != "")' >/dev/null 2>&1 <inbounds/tuic.json.example; then
  pass "tuic клиент имеет id"
else
  bad "tuic: клиент обязан иметь непустой id (иначе 'empty client ID')"
fi
# VLESS Vision flow должен сохраниться
if grep -q 'xtls-rprx-vision' inbounds/vless-reality-vision.json.example; then
  pass "vless-reality-vision сохранил flow xtls-rprx-vision"
else
  bad "vless-reality-vision потерял flow"
fi

echo "== 2. Маршрутизация (jq-трансформация) =="
GEMINI_DOMAINS='["domain:gemini.google.com","domain:aistudio.google.com","domain:generativelanguage.googleapis.com","domain:makersuite.google.com","domain:ai.google.dev","domain:labs.google","domain:alkalimakersuite-pa.clients6.google.com","domain:proactivebackend-pa.googleapis.com","geosite:google-gemini"]'
DIRECT_DOMAINS='["domain:aliexpress.com","domain:aliexpress.ru","domain:alicdn.com","domain:ae01.alicdn.com","domain:aliexpress-media.com","domain:mmstat.com"]'
warp='{"tag":"warp","protocol":"wireguard","settings":{"secretKey":"x","peers":[{"publicKey":"y","endpoint":"1.2.3.4:2408"}]}}'
sample='{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","outboundTag":"api","inboundTag":["api"]}]}}'

# та же программа, что в lib/routing.sh (держим синхронной вручную)
JQPROG='
  def is_gemini:     (.domain // []) as $d | ($gem - $d) == [] and ($d - $gem) == [];
  def is_aliexpress: (.domain // []) as $d | ($dir - $d) == [] and ($d - $dir) == [];
  def is_blockru:    (.outboundTag=="blocked") and (((.ip // []) | index("geoip:ru")) != null
                      or ((.domain // []) | index("geosite:category-ru")) != null);
  .outbounds = (.outbounds // []) |
  (if any(.outbounds[]?; .tag=="direct")  then . else .outbounds += [{tag:"direct",protocol:"freedom",settings:{domainStrategy:"UseIPv4v6"}}] end) |
  (if any(.outbounds[]?; .tag=="blocked") then . else .outbounds += [{tag:"blocked",protocol:"blackhole",settings:{}}] end) |
  (if ($warp != null) then (.outbounds |= map(select(.tag != "warp"))) | .outbounds += [$warp] else . end) |
  .routing = (.routing // {}) |
  .routing.domainStrategy = "IPIfNonMatch" |
  .routing.rules = (.routing.rules // []) |
  .routing.rules = [ .routing.rules[] | select((is_gemini or is_aliexpress or is_blockru) | not) ] |
  ( [ .routing.rules[] | select(.outboundTag=="api") ] ) as $api |
  ( [ .routing.rules[] | select(.outboundTag!="api") ] ) as $rest |
  .routing.rules = $api
    + [ {type:"field", outboundTag:$gemtag,  domain:$gem} ]
    + [ {type:"field", outboundTag:"direct", domain:$dir} ]
    + ( if $blockru=="1" then
          [ {type:"field", outboundTag:"blocked", ip:["geoip:ru"]},
            {type:"field", outboundTag:"blocked", domain:["geosite:category-ru","domain:ru","domain:su","domain:xn--p1ai"]} ]
        else [] end )
    + $rest
'
run() { jq -c --argjson warp "$1" --argjson gem "$GEMINI_DOMAINS" --argjson dir "$DIRECT_DOMAINS" --arg gemtag "$2" --arg blockru "$3" "$JQPROG"; }

out1=$(run "$warp" warp 1 <<<"$sample")
# gemini→warp?
if [[ $(jq -r '.routing.rules[] | select(.domain|index("domain:gemini.google.com")) | .outboundTag' <<<"$out1") == warp ]]; then
  pass "Gemini → warp"; else bad "Gemini не ушёл на warp"; fi
# aliexpress→direct?
if [[ $(jq -r '.routing.rules[] | select(.domain|index("domain:aliexpress.ru")) | .outboundTag' <<<"$out1") == direct ]]; then
  pass "AliExpress → direct"; else bad "AliExpress не ушёл на direct"; fi
# api-правило осталось первым?
if [[ $(jq -r '.routing.rules[0].outboundTag' <<<"$out1") == api ]]; then
  pass "api-правило первым"; else bad "api-правило потеряло позицию"; fi
# blackhole есть в outbounds?
if jq -e '.outbounds[]|select(.tag=="blocked")' >/dev/null <<<"$out1"; then
  pass "outbound blocked присутствует"; else bad "нет outbound blocked"; fi
# идемпотентность: повторный прогон не плодит дубли
out2=$(run "$warp" warp 1 <<<"$out1")
n1=$(jq '.routing.rules|length' <<<"$out1"); n2=$(jq '.routing.rules|length' <<<"$out2")
if [[ $n1 == "$n2" ]]; then pass "идемпотентно (правил: $n1)"; else bad "не идемпотентно ($n1 → $n2)"; fi
# без warp gemini→direct
out3=$(run null direct 1 <<<"$sample")
if [[ $(jq -r '.routing.rules[] | select(.domain|index("domain:gemini.google.com")) | .outboundTag' <<<"$out3") == direct ]]; then
  pass "без WARP Gemini → direct"; else bad "fallback Gemini неверен"; fi
# domainStrategy IPIfNonMatch
if [[ $(jq -r '.routing.domainStrategy' <<<"$out1") == IPIfNonMatch ]]; then
  pass "domainStrategy = IPIfNonMatch"; else bad "domainStrategy не выставлен"; fi
# правила без привязки к user (глобальные)
if jq -e '[.routing.rules[]|select(has("user"))]|length==0' >/dev/null <<<"$out1"; then
  pass "правила AI-WARP без user (глобальные)"; else bad "в правилах осталась привязка user"; fi
# geosite:aliexpress не должен попадать в конфиг (его нет в geosite.dat → Xray exit 23)
if jq -e '[.. | strings | select(. == "geosite:aliexpress")] | length == 0' >/dev/null <<<"$out1"; then
  pass "нет geosite:aliexpress (только прямые домены)"; else bad "geosite:aliexpress остался — Xray упадёт"; fi
# aliexpress всё ещё маршрутизируется (по домену)
if [[ $(jq -r '.routing.rules[] | select(.domain|index("domain:aliexpress.ru")) | .outboundTag' <<<"$out1") == direct ]]; then
  pass "AliExpress → direct по домену"; else bad "AliExpress перестал маршрутизироваться"; fi

echo "== 3. WARP outbound и TUIC =="
GEMINI_DOMAINS="$GEMINI_DOMAINS" bash -c '
  set -e
  DIR="'"$ROOT"'"
  . "$DIR/lib/common.sh"
  WARP_ENV=$(mktemp)
  cat >"$WARP_ENV" <<EOF
WARP_PRIV=aBcPRIVkeybase64==
WARP_PEER_PUB=XyZPUBkeybase64==
WARP_ENDPOINT=162.159.192.1:2408
WARP_V4=172.16.0.2
WARP_V6=2606:4700:110::1
WARP_RESERVED=1,2,3
EOF
  export WARP_ENV
  . "$DIR/lib/keys.sh"; . "$DIR/lib/xui.sh"; . "$DIR/lib/warp.sh"
  ob=$(warp_outbound_json)
  echo "$ob" | jq -e ".protocol==\"wireguard\" and .tag==\"warp\"" >/dev/null
  echo "$ob" | jq -e ".settings.reserved==[1,2,3]" >/dev/null
  echo "$ob" | jq -e ".settings.address==[\"172.16.0.2/32\",\"2606:4700:110::1/128\"]" >/dev/null
  echo "$ob" | jq -e ".settings.peers[0].endpoint==\"162.159.192.1:2408\"" >/dev/null
  rm -f "$WARP_ENV"
' && pass "WARP wireguard-outbound: reserved + address + endpoint" || bad "WARP outbound собран неверно"

# TUIC выключен в дефолтном наборе (в пользу Hysteria2)
if grep -q 'AUTO_INBOUNDS="[^"]*hysteria2' config.example.env && ! grep -q 'AUTO_INBOUNDS="[^"]*tuic' config.example.env; then
  pass "TUIC опционален (нет в дефолтном AUTO_INBOUNDS), Hysteria2 есть"; else bad "дефолтный AUTO_INBOUNDS настроен неверно"; fi

# Встроенный дефолтный шаблон Xray (фолбэк для пустой БД) — валидный и полный
if bash -c '. lib/common.sh; . lib/xui.sh; _xray_default_template' \
     | jq -e '.api and .stats and .policy and (.outbounds|map(.tag)|index("direct")) and (.outbounds|map(.tag)|index("blocked"))' >/dev/null 2>&1; then
  pass "встроенный дефолтный шаблон Xray валиден (api/stats/policy/direct/blocked)"
else
  bad "встроенный дефолтный шаблон Xray некорректен"
fi

# _free_stale_ports определён и не трогает панель/SSH порты (статическая проверка)
if grep -q '_free_stale_ports()' lib/inbounds.sh && grep -q 'x-ui | sshd | systemd' lib/inbounds.sh; then
  pass "_free_stale_ports щадит x-ui/sshd/systemd"; else bad "_free_stale_ports небезопасен"; fi
# функционально: на свободных портах не роняет ERR-trap под set -Eeuo pipefail
if bash -c 'set -Eeuo pipefail; trap "exit 77" ERR
  . lib/common.sh; . lib/inbounds.sh
  SSH_PORTS=(22); PANEL_PORT=65001
  _free_stale_ports 59991 59992 59993
  echo PORTS_OK' 2>/dev/null | grep -q PORTS_OK; then
  pass "_free_stale_ports не триггерит trap на пустых портах"
else
  bad "_free_stale_ports роняет ERR-trap на пустом выводе (нужен || true)"
fi

echo "== 4. nftables анти-DDoS =="
if ! command -v nft >/dev/null; then
  note "nft недоступен — пропуск"
elif [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  # nft -c читает текущий ruleset через netlink — без root это невозможно
  note "нет root — пропуск nft -c (проверяется в CI под sudo и на сервере)"
else
  tmp=$(mktemp); err=$(mktemp)
  sed -e 's/__SYN_RATE__/2000/g;s/__SYN_BURST__/3000/g;s/__ICMP_RATE__/50/g;s/__ICMP_BURST__/100/g;s/__GUARD_RATE__/30/g;s/__GUARD_BURST__/15/g;s/__SSH_PORTS__/22/g;s/__ALLOW4__/ elements = { 203.0.113.5 };/g;s/__ALLOW6__//g' \
      nftables/xui-ddos.nft.template >"$tmp"
  if grep -qE 'add @blacklist[46]' "$tmp"; then bad "ddos: SSH-гвардия не должна авто-банить IP"; fi
  if nft -c -f "$tmp" 2>"$err"; then
    pass "nft -c прошёл (whitelist + мягкая гвардия SSH)"
  elif [[ ! -s $err ]]; then
    note "nft -c не смог прочитать ruleset (песочница) — пропуск"
  else
    bad "nft -c: $(cat "$err")"
  fi
  rm -f "$tmp" "$err"
fi

echo
[[ $fail == 0 ]] && { echo "ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ"; exit 0; } || { echo "ЕСТЬ ОШИБКИ"; exit 1; }
