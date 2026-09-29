# shellcheck shell=bash
# lib/warp.sh — надёжная интеграция Cloudflare WARP БЕЗ зависимости от API панели.
# Регистрируемся напрямую в Cloudflare, строим нативный wireguard-outbound с
# reserved-байтами и умеем проверять здоровье (Gemini через локальный xray-socks)
# и ротировать IP при попадании в «грязный пул».
#
# Требует из других модулей: warn/info/ok/is_json (common.sh), gen_wg_keys (keys.sh),
# _xray_bin (keys.sh). Хранит учётные данные в WARP_ENV.

WARP_ENV=${WARP_ENV:-/etc/x-ui-bootstrap/warp.env}
WARP_API=${WARP_API:-https://api.cloudflareclient.com/v0a4005}
WARP_CLIENT_VER=${WARP_CLIENT_VER:-a-6.30-3596}

# warp_register — регистрирует новый WARP-девайс в Cloudflare, пишет WARP_ENV.
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

  local peer_pub endpoint v4 v6 client_id
  peer_pub=$(jq -r '.config.peers[0].public_key // empty' <<<"$resp")
  endpoint=$(jq -r '.config.peers[0].endpoint.host // empty' <<<"$resp")
  v4=$(jq -r '.config.interface.addresses.v4 // empty' <<<"$resp")
  v6=$(jq -r '.config.interface.addresses.v6 // empty' <<<"$resp")
  client_id=$(jq -r '.config.client_id // empty' <<<"$resp")
  [[ -n $peer_pub && -n $endpoint ]] || { warn "WARP: неполный ответ Cloudflare"; return 1; }
  [[ $endpoint == *:* ]] || endpoint="$endpoint:2408"

  local reserved
  reserved=$(printf '%s' "$client_id" | base64 -d 2>/dev/null | od -An -tu1 | tr -s ' ' '\n' | grep -E '^[0-9]+$' | paste -sd, -)

  install -d -m 700 "$(dirname "$WARP_ENV")"
  ( umask 077; cat >"$WARP_ENV" <<EOF
WARP_PRIV=$priv
WARP_PEER_PUB=$peer_pub
WARP_ENDPOINT=$endpoint
WARP_V4=$v4
WARP_V6=$v6
WARP_RESERVED=$reserved
EOF
  )
  return 0
}

# warp_outbound_json — строит wireguard-outbound (tag=warp) из WARP_ENV.
warp_outbound_json() {
  [[ -r $WARP_ENV ]] || { warn "WARP: нет $WARP_ENV (сначала warp_register)"; return 1; }
  # shellcheck source=/dev/null
  . "$WARP_ENV"
  [[ -n ${WARP_PRIV:-} && -n ${WARP_PEER_PUB:-} && -n ${WARP_ENDPOINT:-} ]] || { warn "WARP: неполный $WARP_ENV"; return 1; }

  local addr='[]'
  [[ -n ${WARP_V4:-} ]] && addr=$(jq -c --arg a "$WARP_V4/32" '. + [$a]' <<<"$addr")
  [[ -n ${WARP_V6:-} ]] && addr=$(jq -c --arg a "$WARP_V6/128" '. + [$a]' <<<"$addr")
  local reserved='[]'; [[ -n ${WARP_RESERVED:-} ]] && reserved="[$WARP_RESERVED]"

  jq -cn --arg sk "$WARP_PRIV" --arg pk "$WARP_PEER_PUB" --arg ep "$WARP_ENDPOINT" \
        --argjson addr "$addr" --argjson res "$reserved" '{
    tag: "warp",
    protocol: "wireguard",
    settings: {
      mtu: 1420,
      secretKey: $sk,
      address: $addr,
      reserved: $res,
      domainStrategy: "ForceIPv4v6",
      noKernelTun: true,
      peers: [{ publicKey: $pk, endpoint: $ep, allowedIPs: ["0.0.0.0/0", "::/0"], keepAlive: 25 }]
    }
  }'
}

# warp_health — проверяет доступность Gemini ЧЕРЕЗ WARP, не трогая маршрутизацию
# хоста: поднимает временный локальный xray (socks→warp) и делает один запрос.
# Возвращает 0 (здоров) или 1 (недоступен/грязный IP → нужна ротация).
warp_health() {
  local bin ob; bin=$(_xray_bin) || { warn "WARP health: нет бинарника xray"; return 2; }
  ob=$(warp_outbound_json) || return 2
  local port=$(( RANDOM % 2000 + 40000 )) cfg; cfg=$(mktemp)
  jq -n --argjson wg "$ob" --argjson port "$port" '{
    log:{loglevel:"warning"},
    inbounds:[{tag:"s",listen:"127.0.0.1",port:$port,protocol:"socks",settings:{auth:"noauth",udp:false}}],
    outbounds:[$wg],
    routing:{rules:[{type:"field",inboundTag:["s"],outboundTag:"warp"}]}
  }' >"$cfg"
  "$bin" run -c "$cfg" >/dev/null 2>&1 &
  local pid=$!; sleep 2
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 \
        --socks5-hostname "127.0.0.1:$port" \
        https://generativelanguage.googleapis.com/ 2>/dev/null || echo 000)
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true; rm -f "$cfg"
  # нормальные ответы Google (даже 404 на пустой путь) = путь через WARP жив;
  # 000 (нет соединения) и 403 (гео/IP-блок) = грязный пул → ротация
  case "$code" in
    200|301|302|400|401|404) return 0 ;;
    *) warn "WARP health: Gemini недоступен через WARP (код $code)"; return 1 ;;
  esac
}

# warp_install_daemon — ставит xui-warp + таймер (health-check + ротация IP).
warp_install_daemon() {
  xui_assets_install
  install -m 700 "$DIR/bin/xui-warp" /usr/local/sbin/xui-warp
  install -m 644 "$DIR/systemd/xui-warp.service" /etc/systemd/system/xui-warp.service
  install -m 644 "$DIR/systemd/xui-warp.timer"   /etc/systemd/system/xui-warp.timer
  systemctl daemon-reload
  systemctl enable --now xui-warp.timer >/dev/null 2>&1 || warn "Не смог включить таймер xui-warp"
  ok "Демон xui-warp активен: health-check Gemini + ротация IP (каждые 6ч)"
}

# warp_swap_in_template — заменяет warp-outbound в xrayTemplateConfig (SQLite) на
# текущий из WARP_ENV и перезапускает панель. Для ротации без потери правил.
warp_swap_in_template() {
  local ob; ob=$(warp_outbound_json) || return 1
  local cur; cur=$(xray_tmpl_get_or_default)
  is_json "$cur" || { warn "WARP: не прочитал шаблон xray"; return 1; }
  local out; out=$(jq -c --argjson w "$ob" '
    .outbounds = ((.outbounds // []) | map(select(.tag != "warp")) + [$w])' <<<"$cur") || return 1
  local tmp; tmp=$(mktemp); printf '%s' "$out" >"$tmp"
  xray_tmpl_set "$tmp"; local rc=$?; rm -f "$tmp"
  return $rc
}
