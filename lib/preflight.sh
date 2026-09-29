# shellcheck shell=bash
# lib/preflight.sh — проверки окружения и установка пакетов.

preflight_checks() {
  [[ $EUID -eq 0 ]] || die "Нужен root"
  [[ -r /etc/os-release ]] || die "Не читается /etc/os-release"
  # shellcheck source=/dev/null
  . /etc/os-release
  [[ "${ID:-} ${ID_LIKE:-}" =~ (debian|ubuntu) ]] || die "Поддерживаются только Debian/Ubuntu (у тебя ${PRETTY_NAME:-?})"
  [[ -f $DIR/config.env ]] || die "Нет config.env — скопируй: cp config.example.env config.env"
  # shellcheck source=/dev/null
  . "$DIR/config.env"

  # значения по умолчанию
  MASK_MODE=${MASK_MODE:-reality}
  BLOCK_RU=${BLOCK_RU:-1}
  ENABLE_BBR=${ENABLE_BBR:-1}
  ENABLE_DDOS=${ENABLE_DDOS:-1}
  ENABLE_WARP=${ENABLE_WARP:-1}
  SSH_KEYS_ONLY=${SSH_KEYS_ONLY:-0}
  PANEL_PUBLIC=${PANEL_PUBLIC:-0}
  PANEL_SSL=${PANEL_SSL:-1}
  PANEL_SSL=${PANEL_SSL:-1}
}

preflight_packages() {
  export DEBIAN_FRONTEND=noninteractive
  local apt=(apt-get -o DPkg::Lock::Timeout=600 -yq)
  info "Обновляю индексы пакетов…"
  "${apt[@]}" update >/dev/null || warn "apt update завершился с предупреждениями"

  local pkgs=(curl ca-certificates jq ufw fail2ban nftables bind9-dnsutils openssl tar iproute2 sqlite3)
  [[ ${MASK_MODE:-} == selfsteal ]] && pkgs+=(nginx certbot)

  info "Устанавливаю пакеты…"
  if ! "${apt[@]}" install "${pkgs[@]}" >/dev/null 2>&1; then
    # fallback: имя dnsutils на старых релизах
    "${apt[@]}" install curl ca-certificates jq ufw fail2ban nftables dnsutils openssl tar iproute2 >/dev/null \
      || die "Не удалось установить базовые пакеты"
    [[ ${MASK_MODE:-} == selfsteal ]] && "${apt[@]}" install nginx certbot >/dev/null 2>&1 || true
  fi
  require curl jq ufw nft openssl
  ok "Пакеты установлены"
}
