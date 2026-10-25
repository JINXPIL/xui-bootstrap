# shellcheck shell=bash
# lib/routing.sh — маршрутизация Xray:
#   • WARP-аутбаунд (Cloudflare) для сервисов, блокирующих IP дата-центров;
#   • Gemini / Google AI  → WARP (чистый IP, иначе вечная загрузка);
#   • AliExpress          → прямой выход VPS (иначе попадает под BLOCK_RU);
#   • BLOCK_RU            → geoip:ru + ru-домены в blackhole;
#   • «дружелюбие к белым спискам» — раскладка так, что QUIC/UDP-протоколы
#     остаются доступными, а критичные к репутации сервисы идут через WARP.

# Домены сервисов, которые блокируют IP хостингов (нужен WARP).
GEMINI_DOMAINS='["domain:gemini.google.com","domain:aistudio.google.com","domain:generativelanguage.googleapis.com","domain:makersuite.google.com","domain:ai.google.dev","domain:labs.google","domain:alkalimakersuite-pa.clients6.google.com","domain:proactivebackend-pa.googleapis.com","geosite:google-gemini"]'

# Сервисы, которые нельзя отправлять в blackhole по BLOCK_RU (нужен прямой выход VPS).
DIRECT_DOMAINS='["domain:aliexpress.com","domain:aliexpress.ru","domain:alicdn.com","domain:ae01.alicdn.com","domain:aliexpress-media.com","domain:mmstat.com","geosite:aliexpress"]'

# routing_register_warp — регистрирует WARP и печатает готовый wireguard-аутбаунд
# (tag=warp) в stdout. Пусто, если не удалось.
routing_register_warp() {
  local priv pub resp
  read -r priv pub < <(gen_wg_keys)
  # API ждёт form-поля privateKey/publicKey
  resp=$(api POST panel/api/xray/warp/reg \
    --data-urlencode "privateKey=$priv" --data-urlencode "publicKey=$pub" 2>/dev/null)
  jq -e '.success' >/dev/null 2>&1 <<<"$resp" || { warn "WARP: регистрация не удалась"; return 1; }

  # obj — строка JSON с полями data{} и config{}
  local obj; obj=$(jq -r '.obj // empty' <<<"$resp")
  [[ -n $obj ]] || { warn "WARP: пустой ответ регистрации"; return 1; }

  local data conf v4 v6 peer_pub endpoint client_id
  data=$(jq -c '.data' <<<"$obj")
  conf=$(jq -c '.config.config // .config' <<<"$obj")
  v4=$(jq -r '.interface.addresses.v4 // empty' <<<"$conf")
  v6=$(jq -r '.interface.addresses.v6 // empty' <<<"$conf")
  peer_pub=$(jq -r '.peers[0].public_key // empty' <<<"$conf")
  endpoint=$(jq -r '.peers[0].endpoint.host // empty' <<<"$conf")
  client_id=$(jq -r '.client_id // empty' <<<"$conf")
  [[ -z $client_id ]] && client_id=$(jq -r '.client_id // empty' <<<"$data")
  local secret; secret=$(jq -r '.private_key // empty' <<<"$data"); [[ -z $secret ]] && secret="$priv"

  [[ -n $peer_pub && -n $endpoint ]] || { warn "WARP: неполная конфигурация от Cloudflare"; return 1; }

  # reserved — байты client_id (base64 → массив int)
  local reserved='[]'
  if [[ -n $client_id ]]; then
    local bytes; bytes=$(printf '%s' "$client_id" | base64 -d 2>/dev/null | od -An -tu1 | tr -s ' ' '\n' | grep -E '^[0-9]+$' | paste -sd, -)
    [[ -n $bytes ]] && reserved="[$bytes]"
  fi

  local addr='[]'
  [[ -n $v4 ]] && addr=$(jq -c --arg a "$v4/32" '. + [$a]' <<<"$addr")
  [[ -n $v6 ]] && addr=$(jq -c --arg a "$v6/128" '. + [$a]' <<<"$addr")

  jq -cn --arg sk "$secret" --arg pk "$peer_pub" --arg ep "$endpoint" \
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
      peers: [{
        publicKey: $pk,
        endpoint: $ep,
        allowedIPs: ["0.0.0.0/0", "::/0"],
        keepAlive: 25
      }]
    }
  }'
}

# routing_apply — применяет маршрутизацию к текущему xraySetting.
# Аргумент: JSON wireguard-аутбаунда WARP (может быть пустым).
routing_apply() {
  local warp_ob="${1:-}"
  local have_warp=0
  [[ -n $warp_ob ]] && jq -e '.tag=="warp"' >/dev/null 2>&1 <<<"$warp_ob" && have_warp=1

  local cur; cur=$(api POST panel/api/xray/ | jq -r '.obj // empty')
  [[ -n $cur ]] || { warn "Не получил текущий xraySetting — пропускаю маршрутизацию"; return 1; }
  local xs; xs=$(jq -c '.xraySetting' <<<"$cur")
  [[ $xs == null || -z $xs ]] && { warn "Пустой xraySetting"; return 1; }

  local gemini_tag="direct"
  ((have_warp)) && gemini_tag="warp"

  # собираем новый xraySetting одним jq. Идемпотентность — по «подписи» правил
  # (совпадению доменных/ip-списков), без служебных полей в конфиге Xray.
  local out
  out=$(jq -c \
    --argjson warp "${warp_ob:-null}" \
    --argjson gem "$GEMINI_DOMAINS" \
    --argjson dir "$DIRECT_DOMAINS" \
    --arg gemtag "$gemini_tag" \
    --arg blockru "${BLOCK_RU:-1}" '
    # маркеры «наших» правил по содержимому
    def is_gemini:     (.domain // []) as $d | ($gem - $d) == [] and ($d - $gem) == [];
    def is_aliexpress: (.domain // []) as $d | ($dir - $d) == [] and ($d - $dir) == [];
    def is_blockru:    (.outboundTag=="blocked") and (((.ip // []) | index("geoip:ru")) != null
                        or ((.domain // []) | index("geosite:category-ru")) != null);

    # --- outbounds: гарантируем direct, blocked, (warp) ---
    .outbounds = (.outbounds // []) |
    (if any(.outbounds[]?; .tag=="direct")  then . else .outbounds += [{tag:"direct", protocol:"freedom",  settings:{domainStrategy:"UseIPv4v6"}}] end) |
    (if any(.outbounds[]?; .tag=="blocked") then . else .outbounds += [{tag:"blocked",protocol:"blackhole",settings:{}}] end) |
    (if ($warp != null)
       then (.outbounds |= map(select(.tag != "warp"))) | .outbounds += [$warp]
       else . end) |

    # --- routing.rules ---
    .routing = (.routing // {}) |
    .routing.rules = (.routing.rules // []) |
    # снимаем ранее добавленные нами правила
    .routing.rules = [ .routing.rules[] | select((is_gemini or is_aliexpress or is_blockru) | not) ] |
    ( [ .routing.rules[] | select(.outboundTag=="api") ] ) as $api |
    ( [ .routing.rules[] | select(.outboundTag!="api") ] ) as $rest |
    .routing.rules =
      $api
      + [ {type:"field", outboundTag:$gemtag,  domain:$gem} ]
      + [ {type:"field", outboundTag:"direct", domain:$dir} ]
      + ( if $blockru=="1" then
            [ {type:"field", outboundTag:"blocked", ip:["geoip:ru"]},
              {type:"field", outboundTag:"blocked", domain:["geosite:category-ru","domain:ru","domain:su","domain:xn--p1ai"]} ]
          else [] end )
      + $rest
  ' <<<"$xs") || { warn "Не собрал новый xraySetting"; return 1; }

  local tmp; tmp=$(mktemp); printf '%s' "$out" >"$tmp"
  local r; r=$(api POST panel/api/xray/update --data-urlencode "xraySetting@$tmp")
  rm -f "$tmp"
  if jq -e '.success' >/dev/null <<<"$r"; then
    ok "Маршрутизация: Gemini→$gemini_tag, AliExpress→direct$( [[ ${BLOCK_RU:-1} == 1 ]] && echo ', RU→blackhole')"
    return 0
  fi
  warn "Маршрутизация не обновилась: $(jq -r '.msg // .' <<<"$r")"
  return 1
}
