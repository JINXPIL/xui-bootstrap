# shellcheck shell=bash
# lib/inbounds.sh — генерация ключей/сертификатов, рендеринг шаблонов и импорт
# инбаундов в панель через API. Здесь же собираются порты для фаервола.
#
# Экспортирует массивы INB_TCP_PORTS / INB_UDP_PORTS и функцию inbounds_provision.

CERT_DIR=${CERT_DIR:-/etc/x-ui-bootstrap}
CERT_PUB="$CERT_DIR/self.pem"
CERT_KEY="$CERT_DIR/self.key"
CERT_PIN=""
CERT_TRUSTED=0            # 1 = доверенный LE-серт (без пиннинга), 0 = самоподписанный
CERT_SNI=""              # SNI для TLS-инбаундов (домен/IP для LE, донор для self-signed)

# Общий материал Reality — генерируется один раз и переиспользуется всеми
# Reality-инбаундами (один донор → один ключ).
REALITY_PRIV=""; REALITY_PUB=""; REALITY_SID=""

INB_TCP_PORTS=(); INB_UDP_PORTS=()

declare -A TEMPLATE_MAP=(
  [reality-vision]=vless-reality-vision.json.example
  [xhttp-reality]=vless-xhttp-reality.json.example
  [grpc-reality]=vless-grpc-reality.json.example
  [trojan-reality]=trojan-reality.json.example
  [ss2022]=shadowsocks-2022.json.example
  [hysteria2]=hysteria2.json.example
  [tuic]=tuic.json.example
  [ws-tls]=vless-ws-tls.json.example
)

# _ensure_tls_cert — сертификат для QUIC/WS-инбаундов.
#  • если ssl_setup выпустил доверенный Let's Encrypt (LE_OK=1) — берём его,
#    без пиннинга, SNI = домен/IP сертификата (клиенты FlClash/Happ его примут);
#  • иначе — самоподписанный EC + SHA-256 pin (для клиентов, уважающих pin).
_ensure_tls_cert() {
  if [[ ${LE_OK:-0} == 1 && -s ${LE_CERT:-} && -s ${LE_KEY:-} ]]; then
    CERT_PUB="$LE_CERT"; CERT_KEY="$LE_KEY"; CERT_TRUSTED=1
    CERT_SNI="${LE_SNI:-$SNI}"; CERT_PIN=""
    return 0
  fi
  CERT_PUB="$CERT_DIR/self.pem"; CERT_KEY="$CERT_DIR/self.key"; CERT_TRUSTED=0
  CERT_SNI="${SNI:-www.microsoft.com}"
  install -d -m 700 "$CERT_DIR"
  if [[ ! -s $CERT_PUB || ! -s $CERT_KEY ]]; then
    info "Генерирую самоподписанный сертификат для QUIC-протоколов (Hysteria2/TUIC)…"
    openssl ecparam -genkey -name prime256v1 -out "$CERT_KEY" 2>/dev/null
    openssl req -new -x509 -key "$CERT_KEY" -out "$CERT_PUB" -days 3650 \
      -subj "/CN=$CERT_SNI" -addext "subjectAltName=DNS:$CERT_SNI" 2>/dev/null \
      || die "Не смог создать самоподписанный сертификат"
    chmod 644 "$CERT_PUB"; chmod 600 "$CERT_KEY"
  fi
  CERT_PIN=$(openssl x509 -in "$CERT_PUB" -outform der 2>/dev/null \
    | openssl dgst -sha256 -binary | openssl base64)
  [[ -n $CERT_PIN ]] || die "Не смог вычислить pin сертификата"
}

# _ensure_reality_keys — общая пара Reality + shortId.
_ensure_reality_keys() {
  [[ -n $REALITY_PRIV ]] && return 0
  read -r REALITY_PRIV REALITY_PUB < <(gen_x25519)
  REALITY_SID=$(gen_shortid 8)
}

# _render NAME TEMPLATE_PATH → печатает готовый JSON инбаунда.
# Все секреты генерируются здесь, порт при конфликте переносится на свободный.
_render() {
  local name="$1" file="$2"
  local t; t=$(<"$file")

  local uuid password ss_key ss_client_key path svc email
  email="$name"
  svc=$(gen_shortid 4)
  path="/$svc"

  # секреты по потребности шаблона
  if [[ $t == *__UUID__* ]]; then uuid=$(gen_uuid); t=${t//__UUID__/$uuid}; fi
  if [[ $t == *__PASSWORD__* ]]; then password=$(gen_password); t=${t//__PASSWORD__/$password}; fi
  if [[ $t == *__SS_KEY__* ]]; then
    local method; method=$(jq -r '.settings.method // "2022-blake3-aes-128-gcm"' <<<"$t")
    ss_key=$(gen_ss_key "$method"); ss_client_key=$(gen_ss_key "$method")
    t=${t//__SS_KEY__/$ss_key}; t=${t//__SS_CLIENT_KEY__/$ss_client_key}
  fi

  # Reality
  if [[ $t == *__PRIVATE_KEY__* || $t == *__PUBLIC_KEY__* ]]; then
    _ensure_reality_keys
    t=${t//__PRIVATE_KEY__/$REALITY_PRIV}
    t=${t//__PUBLIC_KEY__/$REALITY_PUB}
    t=${t//__SHORT_ID__/$REALITY_SID}
  fi

  # TLS-сертификат (Hysteria2/TUIC/WS)
  local tls_sni="$SNI"
  if [[ $t == *__CERT_PUB__* ]]; then
    _ensure_tls_cert
    tls_sni="$CERT_SNI"
    t=${t//__CERT_PUB__/$CERT_PUB}
    t=${t//__CERT_KEY__/$CERT_KEY}
    t=${t//__CERT_PIN__/$CERT_PIN}
  fi

  # общие метки
  t=${t//__TLS_SNI__/$tls_sni}
  t=${t//__SNI__/$SNI}
  t=${t//__DEST__/$DEST}
  t=${t//__SERVER__/$PUBLIC_HOST}
  t=${t//__PATH__/$path}
  t=${t//__SVC__/$svc}
  t=${t//__EMAIL__/$email}

  # не осталось ли незаполненных меток
  local left; left=$(grep -oE '__[A-Z_]+__' <<<"$t" | sort -u | tr '\n' ' ' || true)
  [[ -z $(trim "$left") ]] || die "$name: не заполнены метки: $left"

  # строгая проверка: результат обязан быть валидным JSON
  if ! is_json "$t"; then
    warn "$name: рендер дал невалидный JSON — пропускаю инбаунд"
    return 1
  fi

  # доверенный серт → убираем пиннинг (иначе продление серта сломает клиентов)
  if [[ ${CERT_TRUSTED:-0} == 1 && $t == *pinnedPeerCertSha256* ]]; then
    t=$(jq -c 'if .streamSettings.tlsSettings.settings then
                 .streamSettings.tlsSettings.settings.pinnedPeerCertSha256 = []
                 | .streamSettings.tlsSettings.settings.verifyPeerCertByName = ""
               else . end' <<<"$t") || true
  fi

  # порт: если занят другим инбаундом — переносим на свободный
  local port; port=$(jq -r '.port' <<<"$t")
  if _port_taken "$port"; then
    local np; np=$(free_port)
    warn "$name: порт $port занят — переношу на $np"
    t=$(jq --argjson p "$np" '.port=$p' <<<"$t")
    port=$np
  fi

  printf '%s' "$t"
}

# _port_taken PORT — занят ли порт уже импортированным инбаундом или системой.
_port_taken() {
  local p="$1" x
  for x in "${INB_TCP_PORTS[@]}" "${INB_UDP_PORTS[@]}"; do [[ $x == "$p" ]] && return 0; done
  ss -Hltn "sport = :$p" 2>/dev/null | grep -q . && return 0
  ss -Hlun "sport = :$p" 2>/dev/null | grep -q . && return 0
  return 1
}

# _track_ports JSON — распределяет порт инбаунда в TCP/UDP список для фаервола.
_track_ports() {
  local j="$1" port proto net
  port=$(jq -r '.port' <<<"$j")
  proto=$(jq -r '.protocol' <<<"$j")
  net=$(jq -r '.streamSettings.network // "tcp"' <<<"$j")
  case "$proto:$net" in
    hysteria* | tuic* | wireguard* | amneziawg* | *:kcp | *:hysteria) INB_UDP_PORTS+=("$port") ;;
    *) INB_TCP_PORTS+=("$port")
       # SS с "network":"tcp,udp" слушает и UDP
       if [[ $proto == shadowsocks ]] && jq -e '(.settings.network // "") | test("udp")' >/dev/null <<<"$j"; then
         INB_UDP_PORTS+=("$port")
       fi ;;
  esac
}

# _import NAME JSON — импорт одного инбаунда через API панели.
_import() {
  local name="$1" json="$2"
  local payload; payload=$(jq -c 'del(.id,.nodeId,.originNodeGuid,.fallbackParent)
                                  | .up=0 | .down=0
                                  | .clientStats=((.clientStats//[])|map(.up=0|.down=0))' <<<"$json")
  local tmp; tmp=$(mktemp)
  printf '%s' "$payload" >"$tmp"
  local r; r=$(api POST panel/api/inbounds/import --data-urlencode "data@$tmp")
  rm -f "$tmp"
  if is_json "$r" && jq -e '.success' >/dev/null 2>&1 <<<"$r"; then
    ok "$name → порт $(jq -r '.port' <<<"$json") ($(jq -r '.protocol' <<<"$json"))"
    return 0
  fi
  local msg; msg=$(jq -r '.msg // .' <<<"$r" 2>/dev/null || true)
  [[ -n $msg ]] || msg="нет ответа от API (пустой ответ или не JSON)"
  warn "$name: панель отклонила импорт: $msg"
  return 1
}

# inbounds_provision — основной вход: генерирует и импортирует весь набор.
# Читает AUTO_INBOUNDS (список ключей) и/или готовые inbounds/*.json.
inbounds_provision() {
  local dir="$1"           # каталог с шаблонами (.json.example) и оверрайдами (.json)
  local existing_ports="$2" # порты уже существующих инбаундов (перевод строки)

  # учтём занятые порты уже существующих инбаундов
  local p
  while IFS= read -r p; do [[ -n $p ]] && INB_TCP_PORTS+=("$p"); done <<<"$existing_ports"

  local imported=0

  # 1) автонабор передовых протоколов
  local set="${AUTO_INBOUNDS:-reality-vision xhttp-reality grpc-reality trojan-reality ss2022 hysteria2}"
  local key file json
  for key in $set; do
    key=$(trim "$key"); [[ -z $key ]] && continue
    file="${TEMPLATE_MAP[$key]:-}"
    if [[ -z $file ]]; then warn "Неизвестный протокол '$key' в AUTO_INBOUNDS — пропускаю"; continue; fi
    if [[ ! -f "$dir/$file" ]]; then warn "Нет шаблона $file — пропускаю $key"; continue; fi
    if [[ $key == ws-tls && ${MASK_MODE:-} != selfsteal ]]; then
      warn "ws-tls требует режима selfsteal (нужен домен и сертификат) — пропускаю"; continue
    fi
    json=$(_render "$key" "$dir/$file") || continue
    is_json "$json" || { warn "$key: пропускаю (невалидный JSON после рендера)"; continue; }
    _track_ports "$json"
    _import "$key" "$json" && ((imported++)) || true
  done

  # 2) пользовательские готовые шаблоны inbounds/*.json (ручные оверрайды)
  shopt -s nullglob
  local custom=("$dir"/*.json)
  shopt -u nullglob
  local f name
  for f in "${custom[@]}"; do
    name=$(basename "$f" .json)
    json=$(<"$f")
    # подставим только общие метки маски/сертификата, ключи должны быть в файле
    local ctls="$SNI"
    if [[ $json == *__CERT_PUB__* ]]; then
      _ensure_tls_cert
      ctls="$CERT_SNI"
      json=${json//__CERT_PUB__/$CERT_PUB}; json=${json//__CERT_KEY__/$CERT_KEY}; json=${json//__CERT_PIN__/$CERT_PIN}
    fi
    json=${json//__TLS_SNI__/$ctls}
    json=${json//__SNI__/$SNI}; json=${json//__DEST__/$DEST}; json=${json//__SERVER__/$PUBLIC_HOST}
    if [[ ${CERT_TRUSTED:-0} == 1 && $json == *pinnedPeerCertSha256* ]]; then
      json=$(jq -c 'if .streamSettings.tlsSettings.settings then
                      .streamSettings.tlsSettings.settings.pinnedPeerCertSha256 = []
                      | .streamSettings.tlsSettings.settings.verifyPeerCertByName = ""
                    else . end' <<<"$json") || true
    fi
    if ! is_json "$json" || ! jq -e '.port and .protocol' >/dev/null 2>&1 <<<"$json"; then
      warn "$name.json: не похоже на инбаунд (или невалидный JSON) — пропускаю"; continue
    fi
    local left; left=$(grep -oE '__[A-Z_]+__' <<<"$json" | sort -u | tr '\n' ' ' || true)
    [[ -z $(trim "$left") ]] || { warn "$name.json: не заполнено: $left — пропускаю"; continue; }
    _track_ports "$json"
    _import "$name" "$json" && ((imported++)) || true
  done

  ((imported > 0)) || die "Не импортировано ни одного инбаунда"
  ok "Импортировано инбаундов: $imported"
}
