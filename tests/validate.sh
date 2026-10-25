#!/usr/bin/env bash
# tests/validate.sh — оффлайн-проверки для CI (без реального сервера/API):
#   1) все шаблоны инбаундов — валидный JSON нужной формы;
#   2) маршрутизация (настоящая routing_transform) корректна, идемпотентна и
#      мигрирует правила старых версий без дублей;
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

echo "== 2. Маршрутизация (routing_transform из lib/routing.sh) =="
# Проверяем НАСТОЯЩУЮ функцию, а не её копию: копия молча расходилась с кодом.
# shellcheck source=lib/routing.sh
. lib/routing.sh   # только списки доменов и функции, без побочных эффектов
warp='{"tag":"warp","protocol":"wireguard","settings":{"secretKey":"x","peers":[{"publicKey":"y","endpoint":"1.2.3.4:2408"}]}}'
sample='{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[{"type":"field","outboundTag":"api","inboundTag":["api"]}]}}'
# run WARP_OB [WARP_GOOGLE] [BLOCK_RU] <in — в отдельном bash: common.sh не смешивается с тестом
run() {
  WARP_GOOGLE=${2:-1} BLOCK_RU=${3:-1} bash -c '. lib/common.sh; . lib/routing.sh; routing_transform "$1"' _ "$1"
}
tag_of() { jq -r --arg d "$1" '[.routing.rules[] | select((.domain // []) | index($d))][0].outboundTag // "нет"'; }
pos_of() { jq -r --arg d "$1" '[.routing.rules | to_entries[] | select((.value.domain // []) | index($d)) | .key][0] // -1'; }
same_json() { [[ $(jq -S . <<<"$1") == "$(jq -S . <<<"$2")" ]]; }

out1=$(run "$warp" <<<"$sample")
[[ $(tag_of domain:gemini.google.com <<<"$out1") == warp ]] && pass "Gemini → warp" || bad "Gemini не ушёл на warp"
# вся сессия Google с одного IP: иначе «необычный трафик» (IP VPS ≠ IP Cloudflare)
g_ok=1
for d in domain:google.com domain:gstatic.com domain:googleapis.com domain:googleusercontent.com; do
  [[ $(tag_of "$d" <<<"$out1") == warp ]] || { bad "$d не идёт через warp — вход в Google и Gemini разъедутся по разным IP"; g_ok=0; }
done
[[ $g_ok == 1 ]] && pass "google.com/gstatic/googleapis/googleusercontent → warp"
# YouTube напрямую, и его правило ВЫШЕ WARP-правила (youtubei.googleapis.com ⊂ googleapis.com)
[[ $(tag_of domain:youtube.com <<<"$out1") == direct && $(tag_of domain:googlevideo.com <<<"$out1") == direct ]] \
  && pass "YouTube → direct" || bad "YouTube ушёл не на direct"
yt=$(pos_of domain:youtubei.googleapis.com <<<"$out1"); gw=$(pos_of domain:googleapis.com <<<"$out1")
(( yt >= 0 && gw >= 0 && yt < gw )) && pass "правило YouTube выше правила Google→warp" \
  || bad "правило YouTube ниже Google→warp: API YouTube уйдёт в WARP (yt=$yt, google=$gw)"
[[ $(routing_state <<<"$out1") == google-warp ]] && pass "routing_state = google-warp" || bad "routing_state: $(routing_state <<<"$out1")"
[[ $(tag_of domain:aliexpress.ru <<<"$out1") == direct ]] && pass "AliExpress → direct" || bad "AliExpress не ушёл на direct"
[[ $(jq -r '.routing.rules[0].outboundTag' <<<"$out1") == api ]] && pass "api-правило первым" || bad "api-правило потеряло позицию"
jq -e '.outbounds[]|select(.tag=="blocked")' >/dev/null <<<"$out1" && pass "outbound blocked присутствует" || bad "нет outbound blocked"
# идемпотентность: повторный прогон даёт тот же конфиг
out2=$(run "$warp" <<<"$out1")
same_json "$out1" "$out2" && pass "идемпотентно (правил: $(jq '.routing.rules|length' <<<"$out1"))" || bad "повторный прогон меняет конфиг"

# миграция со старой версии: правило «только Gemini» заменяется, а не дублируется;
# ручные правила пользователя остаются и идут ПОСЛЕ наших
old=$(jq -c --argjson gem "$GEMINI_DOMAINS" '.routing.rules += [{type:"field",outboundTag:"warp",domain:$gem},{type:"field",outboundTag:"direct",domain:["domain:example.org"]}]' <<<"$sample")
[[ $(routing_state <<<"$old") == gemini-warp ]] && pass "старый конфиг распознан как gemini-warp" || bad "routing_state старого конфига: $(routing_state <<<"$old")"
mig=$(run "$warp" <<<"$old")
n_gem=$(jq '[.routing.rules[] | select((.domain // []) | index("domain:gemini.google.com"))] | length' <<<"$mig")
[[ $n_gem == 1 ]] && pass "миграция: одно правило Gemini (старое удалено)" || bad "миграция: правил Gemini = $n_gem"
[[ $(routing_state <<<"$mig") == google-warp ]] && pass "миграция → google-warp" || bad "миграция не перевела Google на warp"
[[ $(jq -r '.routing.rules[-1].domain[0]' <<<"$mig") == domain:example.org ]] && pass "ручное правило сохранено и стоит последним" || bad "ручное правило потеряно или сдвинуто"

# WARP_GOOGLE=0 — как раньше: только Gemini, без YouTube-правила; и обратно без дублей
off=$(run "$warp" 0 <<<"$mig")
[[ $(routing_state <<<"$off") == gemini-warp ]] && pass "WARP_GOOGLE=0 → только Gemini" || bad "WARP_GOOGLE=0: $(routing_state <<<"$off")"
[[ $(tag_of domain:google.com <<<"$off") == нет && $(tag_of domain:youtube.com <<<"$off") == нет ]] \
  && pass "WARP_GOOGLE=0: правил Google/YouTube нет" || bad "WARP_GOOGLE=0 оставил правила Google/YouTube"
same_json "$(run "$warp" 1 <<<"$off")" "$mig" && pass "WARP_GOOGLE 0 → 1 возвращает тот же конфиг" || bad "переключение WARP_GOOGLE оставляет хвосты"

# без WARP: Gemini → direct, лишних правил нет (поведение старых версий)
out3=$(run '' <<<"$sample")
[[ $(tag_of domain:gemini.google.com <<<"$out3") == direct ]] && pass "без WARP Gemini → direct" || bad "fallback Gemini неверен"
[[ $(tag_of domain:google.com <<<"$out3") == нет ]] && pass "без WARP правила Google не создаются" || bad "без WARP появилось правило Google"
jq -e '[.outbounds[] | select(.tag=="warp")] | length == 0' >/dev/null <<<"$out3" && pass "без WARP нет outbound warp" || bad "без WARP в outbounds появился warp"
[[ $(routing_state <<<'') == none && $(routing_state <<<'not json') == none ]] && pass "routing_state: пустой/битый шаблон → none" || bad "routing_state падает на пустом шаблоне"

[[ $(jq -r '.routing.domainStrategy' <<<"$out1") == IPIfNonMatch ]] && pass "domainStrategy = IPIfNonMatch" || bad "domainStrategy не выставлен"
jq -e '[.routing.rules[]|select(has("user"))]|length==0' >/dev/null <<<"$out1" && pass "правила без user (глобальные)" || bad "в правилах осталась привязка user"
# geosite:aliexpress не должен попадать в конфиг (его нет в geosite.dat → Xray exit 23)
jq -e '[.. | strings | select(. == "geosite:aliexpress")] | length == 0' >/dev/null <<<"$out1" \
  && pass "нет geosite:aliexpress (только прямые домены)" || bad "geosite:aliexpress остался — Xray упадёт"
# BLOCK_RU=0 — без blackhole-правил RU
out4=$(run "$warp" 1 0 <<<"$sample")
jq -e '[.routing.rules[] | select(.outboundTag=="blocked")] | length == 0' >/dev/null <<<"$out4" && pass "BLOCK_RU=0 → правил blocked нет" || bad "BLOCK_RU=0 не уважается"

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

# Дефолтный набор = XHTTP + Hysteria2 (без устаревших в Xray 26.x gRPC/Trojan/SS)
auto=$(grep '^AUTO_INBOUNDS=' config.example.env)
if [[ $auto == *xhttp-reality* && $auto == *hysteria2* && $auto != *grpc* \
      && $auto != *trojan* && $auto != *ss2022* && $auto != *tuic* && $auto != *reality-vision* ]]; then
  pass "дефолт = xhttp+hysteria2 (без gRPC/Trojan/SS/TUIC/raw)"; else bad "дефолтный AUTO_INBOUNDS настроен неверно: $auto"; fi
grep -q 'set="${AUTO_INBOUNDS:-xhttp-reality hysteria2}"' lib/inbounds.sh && pass "запасной дефолт в inbounds.sh совпадает с конфигом" || bad "запасной дефолт в inbounds.sh устарел"
# XHTTP-Reality на 443/TCP, Hysteria2 на 443/UDP, gRPC — опциональный на 2087
[[ $(jq -r .port inbounds/vless-xhttp-reality.json.example) == 443 ]] && pass "XHTTP-Reality → 443/TCP" || bad "XHTTP-Reality не на 443"
[[ $(jq -r .port inbounds/hysteria2.json.example) == 443 ]] && pass "Hysteria2 → 443/UDP" || bad "Hysteria2 не на 443"
[[ $(jq -r .port inbounds/vless-grpc-reality.json.example) == 2087 ]] && pass "gRPC-Reality (опционально) → 2087" || bad "gRPC-Reality должен уйти с 443"
jq -e '.streamSettings.xhttpSettings | has("scMaxConcurrentPosts") | not' inbounds/vless-xhttp-reality.json.example >/dev/null \
  && pass "XHTTP без несуществующего в Xray поля scMaxConcurrentPosts" || bad "в XHTTP осталось scMaxConcurrentPosts"
jq -e '[.settings.clients[] | has("method")] | any | not' inbounds/shadowsocks-2022.json.example >/dev/null \
  && pass "SS-2022: у клиентов нет method (Xray: users must have empty method)" || bad "SS-2022: method у клиентов"
# minClientVer выставлен во всех Reality (совместимость с Xray 26.9.9 / Mihomo)
mcv_ok=1
for f in vless-grpc-reality vless-xhttp-reality vless-reality-vision trojan-reality; do
  [[ $(jq -r '.streamSettings.realitySettings.minClientVer // ""' "inbounds/$f.json.example") == 1.0.0 ]] || mcv_ok=0
done
[[ $mcv_ok == 1 ]] && pass "minClientVer=1.0.0 во всех Reality-шаблонах" || bad "minClientVer не выставлен"
# gRPC(TCP 443) и Hysteria2(UDP 443) не конфликтуют — порт-чек различает L4
if bash -c '
  set -Eeuo pipefail; DIR="'"$ROOT"'"
  . "$DIR/lib/common.sh"; . "$DIR/lib/keys.sh"; . "$DIR/lib/inbounds.sh"
  gen_uuid(){ echo 11111111-1111-1111-1111-111111111111; }; gen_x25519(){ echo "P U"; }
  gen_shortid(){ printf 0123abcd; }; gen_password(){ echo pw; }
  _ensure_tls_cert(){ CERT_PUB=/c.pem; CERT_KEY=/c.key; CERT_PIN=X; CERT_TRUSTED=0; CERT_SNI=vk.com; }
  SNI=vk.com; DEST=vk.com:443; PUBLIC_HOST=1.2.3.4; INB_TCP_PORTS=(); INB_UDP_PORTS=()
  g=$(_render xhttp-reality "$DIR/inbounds/vless-xhttp-reality.json.example"); _track_ports "$g"
  h=$(_render hysteria2 "$DIR/inbounds/hysteria2.json.example")
  [[ $(jq -r .port <<<"$g") == 443 && $(jq -r .port <<<"$h") == 443 ]]
' 2>/dev/null; then
  pass "XHTTP/443/tcp + Hysteria2/443/udp сосуществуют (порт не переназначается)"
else
  bad "конфликт портов: TCP и UDP 443 не должны считаться занятыми друг другом"
fi

# Встроенный дефолтный шаблон Xray (фолбэк для пустой БД) — валидный и полный
if bash -c '. lib/common.sh; . lib/xui.sh; _xray_default_template' \
     | jq -e '.api and .stats and .policy and (.outbounds|map(.tag)|index("direct")) and (.outbounds|map(.tag)|index("blocked"))' >/dev/null 2>&1; then
  pass "встроенный дефолтный шаблон Xray валиден (api/stats/policy/direct/blocked)"
else
  bad "встроенный дефолтный шаблон Xray некорректен"
fi

# _free_stale_ports определён и не трогает панель/SSH порты (статическая проверка)
if grep -q '_free_stale_ports()' lib/inbounds.sh && grep -q "xui-warp-\[A-Za-z0-9\]\*" lib/inbounds.sh; then
  pass "_free_stale_ports снимает только свои временные xray (не xray панели)"; else bad "_free_stale_ports небезопасен"; fi
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

echo "== 5. Авто-обновление (geodata + ядро) =="
# скрипт и модуль синтаксически валидны
if bash -n bin/xui-update 2>/dev/null; then pass "bin/xui-update: синтаксис ок"; else bad "bin/xui-update: синтаксическая ошибка"; fi
if bash -n lib/autoupdate.sh 2>/dev/null; then pass "lib/autoupdate.sh: синтаксис ок"; else bad "lib/autoupdate.sh: синтаксическая ошибка"; fi
# xui_api_connect — автономный коннект к API для демонов
if grep -q 'xui_api_connect()' lib/xui.sh; then pass "xui.sh: xui_api_connect определён"; else bad "xui.sh: нет xui_api_connect"; fi
# updater умеет и geodata, и ядро с откатом
if grep -q 'updateGeofile' bin/xui-update; then pass "xui-update: geodata через API updateGeofile"; else bad "xui-update: нет updateGeofile"; fi
if grep -q 'installXray/\$latest' bin/xui-update && grep -q 'installXray/v\$cur' bin/xui-update; then
  pass "xui-update: обновление ядра + откат на прежнюю версию"; else bad "xui-update: нет логики обновления/отката ядра"; fi
if grep -q 'xray.state' bin/xui-update; then pass "xui-update: health-check по xray.state"; else bad "xui-update: нет проверки состояния ядра"; fi
# geodata НЕ подменяет источник (иначе разъедутся имена категорий → Xray exit 23)
if ! grep -qiE 'loyalsoldier|v2ray-rules-dat' bin/xui-update; then
  pass "xui-update: geodata только штатным источником панели"; else bad "xui-update: подмена источника geodata опасна"; fi
# модуль ставит оба таймера и держит ядро выключенным по умолчанию
if grep -q 'xui-geodata.timer' lib/autoupdate.sh && grep -q 'xui-core.timer' lib/autoupdate.sh; then
  pass "autoupdate: таймеры geodata и core создаются"; else bad "autoupdate: таймеры не создаются"; fi
if grep -q 'AUTO_UPDATE_CORE:-0' lib/autoupdate.sh; then pass "autoupdate: ядро выключено по умолчанию (:-0)"; else bad "autoupdate: ядро не должно быть ВКЛ по умолчанию"; fi
if grep -q 'AUTO_UPDATE_GEODATA:-1' lib/autoupdate.sh; then pass "autoupdate: geodata включено по умолчанию (:-1)"; else bad "autoupdate: geodata-дефолт неверен"; fi
# конфиг: флаги присутствуют, ядро по умолчанию 0
if grep -q '^AUTO_UPDATE_GEODATA=1' config.example.env; then pass "config: AUTO_UPDATE_GEODATA=1"; else bad "config: нет AUTO_UPDATE_GEODATA"; fi
if grep -q '^AUTO_UPDATE_CORE=0' config.example.env; then pass "config: AUTO_UPDATE_CORE=0 (безопасный дефолт)"; else bad "config: AUTO_UPDATE_CORE должен быть 0"; fi
# bootstrap подключает и запускает модуль
if grep -qE 'firewall updates autoupdate' bootstrap.sh; then pass "bootstrap: модуль autoupdate подключён"; else bad "bootstrap: autoupdate не в списке модулей"; fi
if grep -q 'autoupdate_install_daemon' bootstrap.sh; then pass "bootstrap: autoupdate_install_daemon вызывается"; else bad "bootstrap: autoupdate_install_daemon не вызывается"; fi

echo "== 6. Токены API (3x-ui ≥ 3.9 перевыпускает токен по имени) =="
names=$(grep -rhoE 'tokenName [a-z-]+|xui_api_connect [a-z-]+' bin lib selfcheck.sh | awk '{print $2}' | sort | uniq -c)
if grep -q 'tokenName xui-fw-sync' bin/xui-fw-sync && grep -q 'xui_api_connect xui-update' bin/xui-update \
   && grep -q 'xui_api_connect xui-selfcheck' selfcheck.sh; then
  pass "у каждого инструмента своё имя токена (fw-sync/update/selfcheck/bootstrap)"
else
  bad "общие имена токенов — fw-sync будет отзывать токены других скриптов: $names"
fi
if grep -q "grep -qi 'SSL'" bin/xui-fw-sync; then bad "xui-fw-sync угадывает схему по слову SSL"; else pass "xui-fw-sync пробует http/https, а не угадывает"; fi
if grep -q "pgrep -x xray" bin/xui-update selfcheck.sh; then bad "pgrep -x xray никогда не совпадёт (xray-linux-amd64)"; else pass "процесс ядра ищется по командной строке"; fi
if grep -q '_xray_up' bin/xui-update; then pass "xui-update: откат только по однозначному сигналу (_xray_up)"; else bad "xui-update: откат по одному ответу API"; fi
if grep -q 'run -test -c "$cfg"' bin/xui-update && grep -q 'обновление ОТМЕНЕНО' bin/xui-update; then
  pass "xui-update core: новое ядро сначала проверяется на живом конфиге (xray run -test)"; else bad "xui-update core без предпроверки ядра"; fi
if grep -q 'pgrep -P "$MAIN" -f xray' selfcheck.sh && ! grep -q "pgrep -f '/usr/local/x-ui/bin/xray'" selfcheck.sh bin/xui-update; then
  pass "xray ищется как дочерний процесс x-ui (cmdline: bin/xray-linux-amd64)"; else bad "поиск процесса xray не совпадёт с реальной командной строкой"; fi
grep -q 'mktemp --suffix=.json' lib/warp.sh && pass "временный конфиг WARP с суффиксом .json (иначе Xray: Failed to get format)" || bad "временный конфиг WARP без .json"

echo "== 7. SSH и fail2ban =="
if grep -q 'PermitRootLogin prohibit-password' lib/security.sh && grep -q 'MaxAuthTries 3' lib/security.sh \
   && grep -q 'sshd -T' lib/security.sh; then
  pass "keys-only: root только по ключу, MaxAuthTries 3, проверка через sshd -T"; else bad "keys-only неполный"; fi
if grep -q 'bantime.increment = true' lib/security.sh && grep -q 'mode     = aggressive' lib/security.sh; then
  pass "fail2ban: прогрессивный бан + aggressive-режим sshd"; else bad "fail2ban без прогрессивного бана"; fi
if grep -q 'failed login: .\*IP="<HOST>"' lib/security.sh && grep -q 'journalmatch = _SYSTEMD_UNIT=x-ui.service' lib/security.sh; then
  pass "fail2ban панели читает формат 3x-ui 3.9 из журнала"; else bad "фильтр панели не совпадает с логом 3x-ui 3.9"; fi
if bash -c '. lib/common.sh; . lib/security.sh; _f2b_backend' | grep -qE '^(systemd|auto)$'; then
  pass "бэкенд fail2ban выбирается по наличию python3-systemd"; else bad "_f2b_backend сломан"; fi

echo "== 8. Клиентский шаблон Mihomo и продление SSL =="
if python3 -I - clients/mihomo.example.yaml <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
assert "global-client-fingerprint" not in d, "global-client-fingerprint удалён в Mihomo"
px = {p["name"]: p for p in d["proxies"]}
x = px["XHTTP-Reality"]
assert x["network"] == "xhttp" and x["port"] == 443
assert x["reality-opts"].get("support-x25519mlkem768") is True, "PQ-флаг должен быть в reality-opts"
assert "support-x25519mlkem768" not in x, "PQ-флаг уровнем выше игнорируется"
assert x.get("client-fingerprint") == "chrome"
for g in d["proxy-groups"]:
    assert all(n in px or n in ("PROXY", "DIRECT") for n in g["proxies"]), g["name"]
PY
then pass "Mihomo: XHTTP 443, PQ-флаг в reality-opts, без удалённого global-client-fingerprint"; else bad "клиентский шаблон Mihomo"; fi
grep -q 'kill -HUP "$p"' lib/ssl.sh && ! grep -q 'reloadcmd "systemctl restart x-ui' lib/ssl.sh \
  && pass "продление: SIGHUP панели вместо рестарта x-ui" || bad "продление всё ещё рестартит x-ui"
grep -q '^XUI_ACME_DAYS_IP=4' lib/ssl.sh && pass "IP-серт продлевается на ~3-и сутки (было ~5-е)" || bad "интервал продления IP-серта"

echo "== 9. Поведенческие тесты =="
for t in warp_test ssl_test idempotency_test update_test xray_test mihomo_test; do
  if bash "tests/$t.sh" >"/tmp/.$t.log" 2>&1; then
    if grep -q 'пропуск' "/tmp/.$t.log" && ! grep -q PASS "/tmp/.$t.log"; then note "$t: $(tail -n1 "/tmp/.$t.log")"
    else pass "$t.sh: $(grep -c PASS "/tmp/.$t.log") проверок"; fi
  else
    bad "$t.sh упал:"; grep -E 'FAIL' "/tmp/.$t.log" | sed 's/^/    /'
  fi
  rm -f "/tmp/.$t.log"
done


echo
[[ $fail == 0 ]] && { echo "ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ"; exit 0; } || { echo "ЕСТЬ ОШИБКИ"; exit 1; }
