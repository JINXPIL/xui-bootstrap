# shellcheck shell=bash
# lib/keys.sh — генерация всего криптографического материала.
# Ключи Reality/x25519 берём у самого Xray (через API панели), чтобы формат
# гарантированно совпал с версией ядра на сервере. Остальное — локально.

# _xray_bin — путь к бинарнику Xray (ставится вместе с 3x-ui).
_xray_bin() {
  command -v xray 2>/dev/null && return 0
  local b; b=$(ls /usr/local/x-ui/bin/xray-linux-* 2>/dev/null | head -n1)
  [[ -n $b && -x $b ]] && { printf '%s' "$b"; return 0; }
  return 1
}

# gen_uuid — UUID v4. Локально: uuidgen → /proc → xray uuid → API панели.
gen_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then uuidgen; return 0; fi
  if [[ -r /proc/sys/kernel/random/uuid ]]; then cat /proc/sys/kernel/random/uuid; return 0; fi
  local bin; if bin=$(_xray_bin); then
    local u; u=$("$bin" uuid 2>/dev/null | tr -d '[:space:]')
    [[ $u =~ ^[0-9a-fA-F-]{36}$ ]] && { printf '%s' "$u"; return 0; }
  fi
  if [[ -n ${XUI_API_READY:-} ]]; then
    local u; u=$(api GET panel/api/server/getNewUUID 2>/dev/null | jq -r '.obj.uuid // empty')
    [[ -n $u ]] && { printf '%s' "$u"; return 0; }
  fi
  die "Нечем сгенерировать UUID"
}

# gen_x25519 — печатает "PRIVATE PUBLIC" (base64, формат Xray Reality/WG).
# ЛОКАЛЬНО через бинарник `xray x25519` (не зависим от API панели). Парсим так
# же, как это делает сама панель: первые две строки, значение после двоеточия.
gen_x25519() {
  local bin priv pub out
  if bin=$(_xray_bin); then
    out=$("$bin" x25519 2>/dev/null)
    priv=$(sed -n '1p' <<<"$out" | cut -d: -f2- | tr -d '[:space:]')
    pub=$(sed -n '2p' <<<"$out" | cut -d: -f2- | tr -d '[:space:]')
    [[ -n $priv && -n $pub ]] && { printf '%s %s\n' "$priv" "$pub"; return 0; }
  fi
  # запасной путь — API панели (если бинарник ещё недоступен)
  if [[ -n ${XUI_API_READY:-} ]]; then
    local resp; resp=$(api GET panel/api/server/getNewX25519Cert 2>/dev/null)
    priv=$(jq -r '.obj.privateKey // empty' <<<"$resp")
    pub=$(jq -r '.obj.publicKey // empty' <<<"$resp")
    [[ -n $priv && -n $pub ]] && { printf '%s %s\n' "$priv" "$pub"; return 0; }
  fi
  die "Не смог сгенерировать пару x25519 (ни xray-бинарником, ни через API)"
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
    printf '%s %s\n' "$priv" "$pub"
    return 0
  fi
  gen_x25519
}
