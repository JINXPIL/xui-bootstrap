# shellcheck shell=bash
# lib/warp.sh — надёжная интеграция Cloudflare WARP БЕЗ зависимости от API панели.
# Регистрируемся напрямую в Cloudflare, строим нативный wireguard-outbound с
# reserved-байтами, проверяем здоровье (временный локальный xray: socks→warp)
# и меняем IP/эндпоинт ТОЛЬКО на проверенно рабочий.
#
# Альтернативный режим: WARP_SOCKS=127.0.0.1:PORT в warp.env — трафик Gemini
# идёт через официальный клиент Cloudflare (warp-svc в proxy-режиме, MASQUE).
#
# Требует из других модулей: warn/info/ok/is_json (common.sh), gen_wg_keys и
# _xray_bin (keys.sh), xray_tmpl_get_or_default/xray_tmpl_set (xui.sh).

WARP_ENV=${WARP_ENV:-/etc/x-ui-bootstrap/warp.env}
WARP_API=${WARP_API:-https://api.cloudflareclient.com/v0a4005}
WARP_CLIENT_VER=${WARP_CLIENT_VER:-a-6.30-3596}
# Проба Google: корень API отвечает 404 — значит путь до Google жив.
WARP_PROBE_URL=${WARP_PROBE_URL:-https://generativelanguage.googleapis.com/}
# Проба туннеля: IP-литерал (без DNS), Cloudflare сообщает warp=on/plus/off.
WARP_TRACE_URL=${WARP_TRACE_URL:-https://1.1.1.1/cdn-cgi/trace}
# Запасные эндпоинты: тот же anycast Cloudflare WARP, другие UDP-порты.
# Хостеры нередко режут UDP 2408 — тогда туннель поднимается на 500/4500/1701.
WARP_FALLBACK_ENDPOINTS=${WARP_FALLBACK_ENDPOINTS:-"162.159.192.1:2408 162.159.192.1:500 162.159.192.1:4500 162.159.192.1:1701"}

# ---------------------------------------------------------------------------
# warp.env: точечная правка ключей (не трогая остальные строки)
# ---------------------------------------------------------------------------
warp_env_set() {
  local k=$1 v=$2 dir tmp
  dir=$(dirname "$WARP_ENV"); install -d -m 700 "$dir"
  tmp=$(mktemp -p "$dir" .warp.XXXXXX)
  grep -v "^$k=" "$WARP_ENV" >"$tmp" 2>/dev/null || true
  printf '%s=%s\n' "$k" "$v" >>"$tmp"
  chmod 600 "$tmp"; mv -f "$tmp" "$WARP_ENV"
}
warp_env_del() {
  local k=$1 tmp
  [[ -r $WARP_ENV ]] || return 0
  tmp=$(mktemp -p "$(dirname "$WARP_ENV")" .warp.XXXXXX)
  grep -v "^$k=" "$WARP_ENV" >"$tmp" 2>/dev/null || true
  chmod 600 "$tmp"; mv -f "$tmp" "$WARP_ENV"
}
warp_env_get() {
  [[ -r $WARP_ENV ]] || return 0
  awk -F= -v k="$1" '$1==k{sub(/^[^=]*=/,""); v=$0} END{printf "%s", v}' "$WARP_ENV"
}

# warp_register — регистрирует новый WARP-девайс в Cloudflare, пишет WARP_ENV.
# Эндпоинт сохраняется IP-литералом: туннель не зависит от системного DNS.
warp_register() {
  local priv pub; read -r priv pub < <(gen_wg_keys)
  [[ -n $priv && -n $pub ]] || { warn "WARP: не сгенерировал ключи"; return 1; }

  local body resp
  body=$(jq -cn --arg k "$pub" --arg tos "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" \
    '{key:$k, tos:$tos, type:"PC", model:"x-ui", name:"xui-bootstrap"}')
  resp=$(curl -fsSL --max-time 20 -X POST "$WARP_API/reg" \
    -H "CF-Client-Version: $WARP_CLIENT_VER" -H "Content-Type: application/json" \
    --data "$body" 2>/dev/null) \
    || { warn "WARP: нет связи с api.cloudflareclient.com (хостер может блокировать)"; return 1; }
  is_json "$resp" || { warn "WARP: некорректный ответ регистрации"; return 1; }

  local peer_pub ep_host ep_v4 endpoint v4 v6 client_id
  peer_pub=$(jq -r '.config.peers[0].public_key // empty' <<<"$resp")
  ep_host=$(jq -r '.config.peers[0].endpoint.host // empty' <<<"$resp")
  ep_v4=$(jq -r '.config.peers[0].endpoint.v4 // empty' <<<"$resp"); ep_v4=${ep_v4%:*}
  v4=$(jq -r '.config.interface.addresses.v4 // empty' <<<"$resp")
  v6=$(jq -r '.config.interface.addresses.v6 // empty' <<<"$resp")
  client_id=$(jq -r '.config.client_id // empty' <<<"$resp")
  if [[ $ep_v4 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    endpoint="$ep_v4:2408"
  else
    endpoint=$ep_host; [[ -z $endpoint || $endpoint == *:* ]] || endpoint="$endpoint:2408"
  fi
  [[ -n $peer_pub && -n $endpoint ]] || { warn "WARP: неполный ответ Cloudflare"; return 1; }

  local reserved
  reserved=$(printf '%s' "$client_id" | base64 -d 2>/dev/null | od -An -tu1 | tr -s ' ' '\n' | grep -E '^[0-9]+$' | paste -sd, - || true)

  local dir tmp; dir=$(dirname "$WARP_ENV"); install -d -m 700 "$dir"
  tmp=$(mktemp -p "$dir" .warp.XXXXXX)
  cat >"$tmp" <<EOF
WARP_PRIV=$priv
WARP_PEER_PUB=$peer_pub
WARP_ENDPOINT=$endpoint
WARP_V4=$v4
WARP_V6=$v6
WARP_RESERVED=$reserved
EOF
  chmod 600 "$tmp"; mv -f "$tmp" "$WARP_ENV"
  return 0
}

# warp_outbound_json — outbound tag=warp из WARP_ENV.
#  • WARP_SOCKS задан  → socks-outbound на официальный клиент (warp-svc);
#  • иначе             → нативный wireguard (эндпоинт можно подменить
#                        через WARP_ENDPOINT_OVERRIDE — для подбора порта).
warp_outbound_json() {
  [[ -r $WARP_ENV ]] || { warn "WARP: нет $WARP_ENV (сначала warp_register)"; return 1; }
  # локальные копии: значения прошлого кандидата не протекают в следующий
  local WARP_PRIV='' WARP_PEER_PUB='' WARP_ENDPOINT='' WARP_V4='' WARP_V6='' WARP_RESERVED='' WARP_SOCKS=''
  # shellcheck source=/dev/null
  . "$WARP_ENV"

  if [[ -n $WARP_SOCKS ]]; then
    local h=${WARP_SOCKS%:*} p=${WARP_SOCKS##*:}
    [[ $p =~ ^[0-9]+$ ]] || { warn "WARP: некорректный WARP_SOCKS=$WARP_SOCKS"; return 1; }
    jq -cn --arg h "$h" --argjson p "$p" '{tag:"warp", protocol:"socks", settings:{address:$h, port:$p}}'
    return 0
  fi

  [[ -n $WARP_PRIV && -n $WARP_PEER_PUB && -n $WARP_ENDPOINT ]] || { warn "WARP: неполный $WARP_ENV"; return 1; }
  local ep=${WARP_ENDPOINT_OVERRIDE:-$WARP_ENDPOINT}
  local addr='[]'
  [[ -n $WARP_V4 ]] && addr=$(jq -c --arg a "$WARP_V4/32" '. + [$a]' <<<"$addr")
  [[ -n $WARP_V6 ]] && addr=$(jq -c --arg a "$WARP_V6/128" '. + [$a]' <<<"$addr")
  local reserved='[]'; [[ -n $WARP_RESERVED ]] && reserved="[$WARP_RESERVED]"

  # domainStrategy в wireguard-outbound Xray больше не поддерживает: домены
  # целей резолвятся ВНУТРИ туннеля (remoteDNS, по умолчанию 1.1.1.1).
  jq -cn --arg sk "$WARP_PRIV" --arg pk "$WARP_PEER_PUB" --arg ep "$ep" \
        --argjson addr "$addr" --argjson res "$reserved" '{
    tag: "warp",
    protocol: "wireguard",
    settings: {
      mtu: 1280,
      secretKey: $sk,
      address: $addr,
      reserved: $res,
      noKernelTun: true,
      peers: [{ publicKey: $pk, endpoint: $ep, allowedIPs: ["0.0.0.0/0", "::/0"], keepAlive: 25 }]
    }
  }'
}

# --- внутренние помощники проверки ---------------------------------------
_warp_free_port() {
  local p i
  for i in $(seq 1 30); do
    p=$(( RANDOM % 10000 + 20000 ))   # 20000–29999: не пересекается с warp-svc (40000)
    ss -Hltn "sport = :$p" 2>/dev/null | grep -q . || { printf '%s' "$p"; return 0; }
  done
  return 1
}
# ждём, пока временный xray реально начнёт слушать (вместо слепого sleep 2)
_warp_wait_port() {
  local port=$1 pid=$2 i
  for i in $(seq 1 30); do
    ss -Hltn "sport = :$port" 2>/dev/null | grep -q . && return 0
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.5
  done
  return 1
}
_warp_stop() {
  local pid=$1; shift
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  rm -f "$@"
}

# warp_health — проверяет путь «xray → WARP → Google» временным локальным xray,
# не трогая маршрутизацию хоста и рабочий x-ui. Две стадии с ретраями:
#   1) туннель: cdn-cgi/trace по IP-литералу должен вернуть warp=on|plus;
#   2) Google: любой HTTP-ответ (200/30x/400/401/404) = путь жив.
# Коды возврата:
#   0 — всё работает;
#   1 — туннель жив, но Google не отвечает/блокирует → смена IP имеет смысл;
#   3 — туннель НЕ поднимается → смена IP бесполезна (смотри порт/UDP/хостера);
#   2 — проверить нельзя (нет xray или учётных данных).
# Побочно выставляет WARP_EGRESS («ip colo») и WARP_HEALTH_DETAIL.
# shellcheck disable=SC2034  # обе переменные читает bin/xui-warp
warp_health() {
  WARP_EGRESS=''; WARP_HEALTH_DETAIL=''
  local bin ob port cfg log pid
  bin=$(_xray_bin) || { WARP_HEALTH_DETAIL="нет бинарника xray"; return 2; }
  ob=$(warp_outbound_json) || { WARP_HEALTH_DETAIL="нет учётных данных WARP"; return 2; }
  port=$(_warp_free_port) || { WARP_HEALTH_DETAIL="нет свободного локального порта"; return 2; }
  cfg=$(mktemp); log=$(mktemp)
  jq -n --argjson wg "$ob" --argjson port "$port" '{
    log:{loglevel:"warning"},
    inbounds:[{tag:"s",listen:"127.0.0.1",port:$port,protocol:"socks",settings:{auth:"noauth",udp:false}}],
    outbounds:[$wg],
    routing:{rules:[{type:"field",inboundTag:["s"],outboundTag:"warp"}]}
  }' >"$cfg"
  "$bin" run -c "$cfg" >"$log" 2>&1 &
  pid=$!
  if ! _warp_wait_port "$port" "$pid"; then
    WARP_HEALTH_DETAIL="временный xray не запустился: $(tail -n 3 "$log" | tr '\n' ' ')"
    _warp_stop "$pid" "$cfg" "$log"; return 2
  fi

  # --- стадия 1: туннель ---
  local trace='' state='' try
  for try in 1 2 3; do
    trace=$(curl -s --connect-timeout 8 --max-time 15 --socks5-hostname "127.0.0.1:$port" "$WARP_TRACE_URL" 2>/dev/null || true)
    state=$(awk -F= '$1=="warp"{print $2}' <<<"$trace")
    [[ -n $state ]] && break
    sleep $(( try * 2 ))
  done
  if [[ $state != on && $state != plus ]]; then
    WARP_HEALTH_DETAIL="туннель не отвечает${state:+ (warp=$state)}; xray: $(grep -iE 'error|fail|handshake|timeout' "$log" | tail -n 2 | tr '\n' ' ')"
    _warp_stop "$pid" "$cfg" "$log"; return 3
  fi
  WARP_EGRESS="$(awk -F= '$1=="ip"{print $2}' <<<"$trace") $(awk -F= '$1=="colo"{print $2}' <<<"$trace")"

  # --- стадия 2: Google ---
  local code=000
  for try in 1 2 3; do
    code=$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 8 --max-time 20 \
           --socks5-hostname "127.0.0.1:$port" "$WARP_PROBE_URL" 2>/dev/null || true)
    code=${code:-000}               # curl сам печатает 000 при сбое — не дублируем
    [[ $code != 000 ]] && break
    sleep $(( try * 2 ))
  done
  _warp_stop "$pid" "$cfg" "$log"
  WARP_HEALTH_DETAIL="google=$code"
  case "$code" in
    200|301|302|400|401|404) return 0 ;;
    *) return 1 ;;
  esac
}

# warp_find_endpoint — подбирает рабочий эндпоинт (порт) для ТЕКУЩИХ ключей.
# Печатает найденный эндпоинт и возвращает 0; иначе 1.
warp_find_endpoint() {
  local cur ep rc
  cur=$(warp_env_get WARP_ENDPOINT)
  for ep in $WARP_FALLBACK_ENDPOINTS; do
    [[ $ep == "$cur" ]] && continue
    rc=0; WARP_ENDPOINT_OVERRIDE=$ep warp_health || rc=$?
    if [[ $rc == 0 || $rc == 1 ]]; then printf '%s' "$ep"; return 0; fi
  done
  return 1
}

# warp_rotate_verified [N] — до N кандидатов: регистрирует каждого во временный
# файл, проверяет и подменяет рабочий WARP ТОЛЬКО здоровым. Если здорового нет —
# рабочий конфиг и панель не трогаются (никаких лишних рестартов x-ui).
warp_rotate_verified() {
  local n=${1:-2} i rc cand saved=$WARP_ENV dir
  dir=$(dirname "$WARP_ENV"); install -d -m 700 "$dir"
  for (( i = 1; i <= n; i++ )); do
    cand=$(mktemp -p "$dir" .warp.cand.XXXXXX)
    WARP_ENV=$cand
    rc=9
    if warp_register; then
      rc=0; warp_health || rc=$?
    fi
    WARP_ENV=$saved
    if [[ $rc == 0 ]]; then
      chmod 600 "$cand"; mv -f "$cand" "$WARP_ENV"
      warp_swap_in_template && return 0
      return 1
    fi
    rm -f "$cand"
    info "WARP: кандидат $i/$n не прошёл проверку (код $rc) — рабочий не трогаю"
    if (( i < n )); then sleep 3; fi
  done
  return 1
}

# warp_install_daemon — ставит xui-warp + таймер (health-check + ротация IP).
warp_install_daemon() {
  xui_assets_install
  install -m 700 "$DIR/bin/xui-warp" /usr/local/sbin/xui-warp
  install -m 644 "$DIR/systemd/xui-warp.service" /etc/systemd/system/xui-warp.service
  install -m 644 "$DIR/systemd/xui-warp.timer"   /etc/systemd/system/xui-warp.timer
  systemctl daemon-reload
  systemctl enable --now xui-warp.timer >/dev/null 2>&1 || warn "Не смог включить таймер xui-warp"
  ok "Демон xui-warp активен: проверка WARP каждые 6ч (замена только на проверенно рабочий)"
}

# warp_swap_in_template — заменяет warp-outbound в xrayTemplateConfig (SQLite) на
# текущий из WARP_ENV и перезапускает панель. Вызывается ТОЛЬКО при улучшении.
warp_swap_in_template() {
  local ob; ob=$(warp_outbound_json) || return 1
  local cur; cur=$(xray_tmpl_get_or_default)
  is_json "$cur" || { warn "WARP: не прочитал шаблон xray"; return 1; }
  local out; out=$(jq -c --argjson w "$ob" '
    .outbounds = ((.outbounds // []) | map(select(.tag != "warp")) + [$w])' <<<"$cur") || return 1
  local tmp; tmp=$(mktemp); printf '%s' "$out" >"$tmp"
  local rc=0; xray_tmpl_set "$tmp" || rc=$?
  rm -f "$tmp"
  return $rc
}
