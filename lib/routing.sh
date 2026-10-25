# shellcheck shell=bash
# lib/routing.sh — маршрутизация Xray через ПРЯМУЮ запись xrayTemplateConfig в
# SQLite (надёжнее, чем API /panel/api/xray, который иногда не отвечает):
#   • Gemini / Google AI  → WARP (чистый IP, иначе вечная загрузка);
#   • google.com, gstatic.com, googleapis.com, googleusercontent.com → тоже WARP
#     (WARP_GOOGLE=1, по умолчанию). Если через WARP идёт только Gemini, а вход в
#     аккаунт и cookie Google — с IP VPS, Google видит одну сессию с двух адресов
#     и показывает «Наши системы обнаружили необычный трафик» (IP ≠ IP);
#   • YouTube             → прямой выход VPS (видео в WARP медленнее; у YouTube
#                           свои cookie на youtube.com, с google.com не смешиваются);
#   • AliExpress          → прямой выход VPS (иначе попадает под BLOCK_RU);
#   • BLOCK_RU            → geoip:ru + ru-домены в blackhole;
#   • routing.domainStrategy = IPIfNonMatch (правила по IP срабатывают и на домены).
# WARP-outbound строит lib/warp.sh (нативно, без API панели). Правила глобальные —
# без привязки к конкретному user.

# Старый список правила Gemini. НЕ МЕНЯТЬ: по точному совпадению набора доменов
# обновление узнаёт и удаляет правило, созданное прошлыми версиями.
GEMINI_DOMAINS='["domain:gemini.google.com","domain:aistudio.google.com","domain:generativelanguage.googleapis.com","domain:makersuite.google.com","domain:ai.google.dev","domain:labs.google","domain:alkalimakersuite-pa.clients6.google.com","domain:proactivebackend-pa.googleapis.com","geosite:google-gemini"]'
# Сессия Google: вход в аккаунт, cookie, капча, статика и API.
GOOGLE_DOMAINS='["domain:google.com","domain:gstatic.com","domain:googleapis.com","domain:googleusercontent.com"]'
# YouTube остаётся на прямом выходе. Правило стоит ВЫШЕ WARP-правила: API YouTube
# (youtubei.googleapis.com) иначе попал бы в googleapis.com → WARP.
YOUTUBE_DOMAINS='["domain:youtube.com","domain:youtu.be","domain:youtube-nocookie.com","domain:googlevideo.com","domain:ytimg.com","domain:ggpht.com","domain:youtubei.googleapis.com","domain:youtube.googleapis.com"]'
# Только прямые доменные правила: категории geosite:aliexpress в стандартном
# geosite.dat нет (Xray падает с exit 23 "failed to check code ALIEXPRESS").
DIRECT_DOMAINS='["domain:aliexpress.com","domain:aliexpress.ru","domain:alicdn.com","domain:ae01.alicdn.com","domain:aliexpress-media.com","domain:mmstat.com"]'

# routing_transform [WARP_OUTBOUND_JSON] — xrayTemplateConfig со stdin → новый на
# stdout. Чистая функция: без БД и рестартов (её же вызывают тесты).
# Без WARP Gemini идёт direct, а Google/YouTube-правила не создаются (как раньше).
routing_transform() {
  local warp_ob="${1:-}" have_warp=0 gemtag=direct google=0
  [[ -n $warp_ob ]] && is_json "$warp_ob" && jq -e '.tag=="warp"' >/dev/null 2>&1 <<<"$warp_ob" && have_warp=1
  if ((have_warp)); then
    gemtag=warp
    is_true "${WARP_GOOGLE:-1}" && google=1
  else
    warp_ob=null
  fi
  jq -c \
    --argjson warp "$warp_ob" \
    --argjson gem "$GEMINI_DOMAINS" \
    --argjson goog "$GOOGLE_DOMAINS" \
    --argjson yt "$YOUTUBE_DOMAINS" \
    --argjson dir "$DIRECT_DOMAINS" \
    --arg gemtag "$gemtag" \
    --arg google "$google" \
    --arg blockru "${BLOCK_RU:-1}" '
    def same($a):   (.domain // []) as $d | ($a - $d) == [] and ($d - $a) == [];
    # свои правила узнаём по точному набору доменов: и старое «только Gemini»,
    # и новое «Gemini + Google» — переключение WARP_GOOGLE не оставляет дублей
    def ours:       same($gem) or same($gem + $goog) or same($yt) or same($dir);
    def is_blockru: (.outboundTag=="blocked") and (((.ip // []) | index("geoip:ru")) != null
                    or ((.domain // []) | index("geosite:category-ru")) != null);

    .outbounds = (.outbounds // []) |
    (if any(.outbounds[]?; .tag=="direct")  then . else .outbounds += [{tag:"direct", protocol:"freedom", settings:{}, streamSettings:{sockopt:{domainStrategy:"UseIPv4v6"}}}] end) |
    (if any(.outbounds[]?; .tag=="blocked") then . else .outbounds += [{tag:"blocked",protocol:"blackhole",settings:{}}] end) |
    (if ($warp != null)
       then (.outbounds |= map(select(.tag != "warp"))) | .outbounds += [$warp]
       else . end) |

    .routing = (.routing // {}) |
    .routing.domainStrategy = "IPIfNonMatch" |
    .routing.rules = (.routing.rules // []) |
    .routing.rules = [ .routing.rules[] | select((ours or is_blockru) | not) ] |
    ( [ .routing.rules[] | select(.outboundTag=="api") ] ) as $api |
    ( [ .routing.rules[] | select(.outboundTag!="api") ] ) as $rest |
    .routing.rules =
      $api
      + ( if $google=="1" then [ {type:"field", outboundTag:"direct", domain:$yt} ] else [] end )
      + [ {type:"field", outboundTag:$gemtag, domain:(if $google=="1" then $gem + $goog else $gem end)} ]
      + [ {type:"field", outboundTag:"direct", domain:$dir} ]
      + ( if $blockru=="1" then
            [ {type:"field", outboundTag:"blocked", ip:["geoip:ru"]},
              {type:"field", outboundTag:"blocked", domain:["geosite:category-ru","domain:ru","domain:su","domain:xn--p1ai"]} ]
          else [] end )
      + $rest
  '
}

# routing_state — по xrayTemplateConfig со stdin печатает, куда идёт Gemini:
#   google-warp   — Gemini и вся сессия Google через WARP;
#   gemini-warp   — через WARP только Gemini (вход в Google — с IP VPS);
#   gemini-direct — Gemini мимо WARP;
#   none          — правила Gemini нет (или шаблон пуст/не читается).
routing_state() {
  local s
  s=$(jq -r '
    [ (.routing.rules // [])[] | select((.domain // []) | index("domain:gemini.google.com")) ][0] as $r
    | if $r == null then "none"
      elif $r.outboundTag != "warp" then "gemini-direct"
      elif (($r.domain // []) | index("domain:google.com")) != null then "google-warp"
      else "gemini-warp" end' 2>/dev/null)
  printf '%s' "${s:-none}"
}

# routing_apply [WARP_OUTBOUND_JSON] — применяет маршрутизацию к xrayTemplateConfig
# (один перезапуск x-ui внутри xray_tmpl_set).
routing_apply() {
  local warp_ob="${1:-}"

  # Шаблон: БД → API → дефолт панели → встроенный дефолт. В свежей 3.8.5 ключа
  # xrayTemplateConfig в settings нет до первого ручного сохранения в UI —
  # поэтому берём дефолтный шаблон и создаём запись сами (INSERT в xray_tmpl_set).
  local xs; xs=$(xray_tmpl_get_or_default)
  is_json "$xs" || { warn "Не удалось получить базовый шаблон Xray — пропускаю маршрутизацию"; return 1; }

  local out
  out=$(routing_transform "$warp_ob" <<<"$xs") || { warn "Не собрал новый xrayTemplateConfig"; return 1; }
  is_json "$out" || { warn "Итоговый xrayTemplateConfig невалиден — не применяю"; return 1; }

  local what
  case $(routing_state <<<"$out") in
    google-warp) what="Gemini и Google→warp, YouTube→direct" ;;
    gemini-warp) what="Gemini→warp (только Gemini, WARP_GOOGLE=0)" ;;
    *)           what="Gemini→direct" ;;
  esac

  local tmp; tmp=$(mktemp); printf '%s' "$out" >"$tmp"
  if xray_tmpl_set "$tmp"; then
    rm -f "$tmp"
    ok "Маршрутизация (SQLite): $what, AliExpress→direct$( [[ ${BLOCK_RU:-1} == 1 ]] && echo ', RU→blackhole'), domainStrategy=IPIfNonMatch"
    return 0
  fi
  rm -f "$tmp"
  warn "Не удалось записать xrayTemplateConfig"
  return 1
}
