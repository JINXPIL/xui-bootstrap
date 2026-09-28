# shellcheck shell=bash
# lib/keys.sh — генерация всего криптографического материала.
# Ключи Reality/x25519 берём у самого Xray (через API панели), чтобы формат
# гарантированно совпал с версией ядра на сервере. Остальное — локально.

# gen_uuid — UUID v4. Приоритет: xray-совместимый API → uuidgen → /proc.
gen_uuid() {
  if [[ -n ${XUI_API_READY:-} ]]; then
    local u; u=$(api GET panel/api/server/getNewUUID 2>/dev/null | jq -r '.obj.uuid // empty')
    [[ -n $u ]] && { printf '%s' "$u"; return 0; }
  fi
  if command -v uuidgen >/dev/null 2>&1; then uuidgen; return 0; fi
  if [[ -r /proc/sys/kernel/random/uuid ]]; then cat /proc/sys/kernel/random/uuid; return 0; fi
  die "Нечем сгенерировать UUID"
}

# gen_x25519 — печатает "PRIVATE PUBLIC" (base64, формат Xray Reality/WG).
# Используем API панели: команда `xray x25519` конкретной версии ядра.
gen_x25519() {
  [[ -n ${XUI_API_READY:-} ]] || die "gen_x25519 требует поднятого API панели"
  local resp priv pub
  resp=$(api GET panel/api/server/getNewX25519Cert 2>/dev/null)
  priv=$(jq -r '.obj.privateKey // empty' <<<"$resp")
  pub=$(jq -r '.obj.publicKey // empty' <<<"$resp")
  [[ -n $priv && -n $pub ]] || die "Панель не выдала пару ключей x25519"
  printf '%s %s' "$priv" "$pub"
}

# gen_shortid [BYTES] — hex shortId для Reality (по умолчанию 8 байт = 16 hex).
gen_shortid() {
  local bytes="${1:-8}"
  openssl rand -hex "$bytes"
}

# gen_password [BYTES] — url-safe пароль (Trojan/TUIC и т.п.).
gen_password() {
  local bytes="${1:-16}"
  openssl rand -base64 "$bytes" | tr -d '\n=+/' | cut -c1-24
}

# gen_ss_key METHOD — ключ для Shadowsocks-2022 нужной длины.
#   2022-blake3-aes-128-gcm         → 16 байт
#   2022-blake3-aes-256-gcm         → 32 байта
#   2022-blake3-chacha20-poly1305   → 32 байта
gen_ss_key() {
  local method="$1" len=32
  case "$method" in
    *aes-128-gcm) len=16 ;;
    *aes-256-gcm | *chacha20-poly1305) len=32 ;;
  esac
  openssl rand -base64 "$len"
}

# gen_wg_keys — печатает "PRIVATE PUBLIC" для WireGuard/AmneziaWG.
# WG-ключи — это тот же curve25519 в base64, что и Reality x25519.
gen_wg_keys() {
  if command -v wg >/dev/null 2>&1; then
    local priv pub
    priv=$(wg genkey)
    pub=$(wg pubkey <<<"$priv")
    printf '%s %s' "$priv" "$pub"
    return 0
  fi
  gen_x25519
}
