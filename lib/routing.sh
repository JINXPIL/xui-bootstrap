# shellcheck shell=bash
# lib/routing.sh — маршрутизация Xray через ПРЯМУЮ запись xrayTemplateConfig в
# SQLite (надёжнее, чем API /panel/api/xray, который иногда не отвечает):
#   • Gemini / Google AI  → WARP (чистый IP, иначе вечная загрузка);
#   • AliExpress          → прямой выход VPS (иначе попадает под BLOCK_RU);
#   • BLOCK_RU            → geoip:ru + ru-домены в blackhole;
#   • routing.domainStrategy = IPIfNonMatch (правила по IP срабатывают и на домены).
# WARP-outbound строит lib/warp.sh (нативно, без API панели). Правило AI-WARP
# глобальное — без привязки к конкретному user.

GEMINI_DOMAINS='["domain:gemini.google.com","domain:aistudio.google.com","domain:generativelanguage.googleapis.com","domain:makersuite.google.com","domain:ai.google.dev","domain:labs.google","domain:alkalimakersuite-pa.clients6.google.com","domain:proactivebackend-pa.googleapis.com","geosite:google-gemini"]'
DIRECT_DOMAINS='["domain:aliexpress.com","domain:aliexpress.ru","domain:alicdn.com","domain:ae01.alicdn.com","domain:aliexpress-media.com","domain:mmstat.com","geosite:aliexpress"]'

# routing_apply [WARP_OUTBOUND_JSON] — применяет маршрутизацию к xrayTemplateConfig.
routing_apply() {
  local warp_ob="${1:-}"
  local have_warp=0
  [[ -n $warp_ob ]] && is_json "$warp_ob" && jq -e '.tag=="warp"' >/dev/null 2>&1 <<<"$warp_ob" && have_warp=1

  local xs; xs=$(xray_tmpl_get)
  if ! is_json "$xs"; then
    # запасной путь — через API панели
    xs=$(api POST panel/api/xray/ 2>/dev/null | jq -c '.obj // empty | fromjson? | .xraySetting' 2>/dev/null || true)
  fi
  is_json "$xs" || { warn "Не прочитал xrayTemplateConfig (ни из SQLite, ни из API) — пропускаю маршрутизацию"; return 1; }

  local gemtag="direct"; ((have_warp)) && gemtag="warp"

  local out
  out=$(jq -c \
    --argjson warp "${warp_ob:-null}" \
    --argjson gem "$GEMINI_DOMAINS" \
    --argjson dir "$DIRECT_DOMAINS" \
    --arg gemtag "$gemtag" \
    --arg blockru "${BLOCK_RU:-1}" '
    def is_gemini:     (.domain // []) as $d | ($gem - $d) == [] and ($d - $gem) == [];
    def is_aliexpress: (.domain // []) as $d | ($dir - $d) == [] and ($d - $dir) == [];
    def is_blockru:    (.outboundTag=="blocked") and (((.ip // []) | index("geoip:ru")) != null
                        or ((.domain // []) | index("geosite:category-ru")) != null);

    .outbounds = (.outbounds // []) |
    (if any(.outbounds[]?; .tag=="direct")  then . else .outbounds += [{tag:"direct", protocol:"freedom",  settings:{domainStrategy:"UseIPv4v6"}}] end) |
    (if any(.outbounds[]?; .tag=="blocked") then . else .outbounds += [{tag:"blocked",protocol:"blackhole",settings:{}}] end) |
    (if ($warp != null)
       then (.outbounds |= map(select(.tag != "warp"))) | .outbounds += [$warp]
       else . end) |

    .routing = (.routing // {}) |
    .routing.domainStrategy = "IPIfNonMatch" |
    .routing.rules = (.routing.rules // []) |
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
  ' <<<"$xs") || { warn "Не собрал новый xrayTemplateConfig"; return 1; }

  is_json "$out" || { warn "Итоговый xrayTemplateConfig невалиден — не применяю"; return 1; }

  local tmp; tmp=$(mktemp); printf '%s' "$out" >"$tmp"
  if xray_tmpl_set "$tmp"; then
    rm -f "$tmp"
    ok "Маршрутизация (SQLite): Gemini→$gemtag, AliExpress→direct$( [[ ${BLOCK_RU:-1} == 1 ]] && echo ', RU→blackhole'), domainStrategy=IPIfNonMatch"
    return 0
  fi
  rm -f "$tmp"
  warn "Не удалось записать xrayTemplateConfig"
  return 1
}
