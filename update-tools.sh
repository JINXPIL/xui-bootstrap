#!/usr/bin/env bash
# ============================================================================
#  update-tools.sh — обновить демоны и библиотеки xui-bootstrap на УЖЕ
#  развёрнутом сервере. НЕ трогает инбаунды, ключи, WARP-регистрацию,
#  маршрутизацию и саму панель (x-ui не перезапускается) — только проверяет
#  и подсказывает, что исправить.
#
#    git pull && sudo bash update-tools.sh
#
#  Опции:
#    --fix-ocsp   обнулить ocspStapling у существующих TLS-инбаундов (убирает
#                 варнинг «ignoring invalid OCSP»; ОДИН перезапуск x-ui)
#    --routing    пересобрать маршрутизацию Gemini/Google/YouTube/AliExpress
#                 по текущей версии (WARP проверяется заранее; ОДИН перезапуск)
# ============================================================================
set -Eeuo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX_OCSP=0
ROUTING=0
for a in "$@"; do
  case $a in
    --fix-ocsp) FIX_OCSP=1 ;;
    --routing)  ROUTING=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "Неизвестный параметр: $a (см. --help)" >&2; exit 2 ;;
  esac
done
for m in common xui keys warp security autoupdate ssl routing; do
  # shellcheck source=/dev/null
  . "$DIR/lib/$m.sh"
done
[[ $EUID -eq 0 ]] || die "Запусти от root: sudo bash update-tools.sh"
[[ -x $XUI_BIN ]] || die "x-ui не установлен — сначала bootstrap.sh"
# значения из командной строки важнее config.env (SSH_KEYS_ONLY=1 bash update-tools.sh)
_cli_keys_only=${SSH_KEYS_ONLY:-}
# shellcheck source=/dev/null
[[ -r $DIR/config.env ]] && . "$DIR/config.env"
[[ -n $_cli_keys_only ]] && SSH_KEYS_ONLY=$_cli_keys_only

step "Библиотеки и демоны"
xui_assets_install
install -m 700 "$DIR/bin/xui-fw-sync" /usr/local/sbin/xui-fw-sync
ok "xui-fw-sync: свой API-токен, http/https определяется пробой"
if [[ -x /usr/local/sbin/xui-warp || -r $WARP_ENV ]]; then
  install -m 700 "$DIR/bin/xui-warp" /usr/local/sbin/xui-warp
  install -m 644 "$DIR/systemd/xui-warp.service" /etc/systemd/system/xui-warp.service
  install -m 644 "$DIR/systemd/xui-warp.timer"   /etc/systemd/system/xui-warp.timer
  ok "xui-warp: двухстадийная проверка, рестарт панели только при улучшении"
fi
autoupdate_install_daemon
systemctl daemon-reload

step "SSL: продление"
ssl_refresh_renewal

step "fail2ban"
command -v apt-get >/dev/null && apt-get -o DPkg::Lock::Timeout=120 -yq install python3-systemd >/dev/null 2>&1 || true
mapfile -t SSH_PORTS < <(security_ssh_ports)
(( ${#SSH_PORTS[@]} )) || SSH_PORTS=(22)
ADMIN_IP=$(awk '{print $1}' <<<"${SSH_CONNECTION:-${SSH_CLIENT:-}}")
[[ ${ADMIN_IP:-} =~ ^[0-9a-fA-F:.]+$ ]] || ADMIN_IP=''
# панель публична, если слушает не только localhost
listen=$("$XUI_BIN" setting -getListen 2>/dev/null | awk '/listenIP:/{print $2}' || true)
if [[ -z $listen || $listen == 0.0.0.0 || $listen == :: ]]; then PANEL_PUBLIC=1; else PANEL_PUBLIC=${PANEL_PUBLIC:-0}; fi
PANEL_PORT=$("$XUI_BIN" setting -show 2>/dev/null | awk '$1=="port:"{print $2}' || true)
[[ -n $PANEL_PORT ]] || PANEL_PORT=$(_panel_port_fallback)
export ADMIN_IP PANEL_PUBLIC PANEL_PORT
security_fail2ban SSH_PORTS

step "SSH"
if is_true "${SSH_KEYS_ONLY:-0}"; then
  security_ssh_keys_only
else
  pa=$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2}' || true)
  [[ $pa == no ]] && ok "SSH: вход по паролю уже выключен" \
    || warn "SSH: вход по паролю включён. Добавь ключ и запусти: SSH_KEYS_ONLY=1 bash update-tools.sh"
fi

step "OCSP в существующих инбаундах"
n=$(xui_fix_ocsp --dry-run 2>/dev/null || echo 0)
RESTARTED=0
if [[ ${n:-0} -eq 0 ]]; then
  ok "ocspStapling: исправлять нечего"
elif [[ $FIX_OCSP == 1 ]]; then
  systemctl stop x-ui
  n=$(xui_fix_ocsp)
  systemctl start x-ui; RESTARTED=1
  ok "ocspStapling → 0 в инбаундах: $n (x-ui перезапущен один раз)"
else
  warn "ocspStapling ≠ 0 в инбаундах: $n — отсюда варнинг «ignoring invalid OCSP». Исправить: bash update-tools.sh --fix-ocsp"
fi

step "Маршрутизация Gemini/Google"
# Куда сейчас идёт Gemini и куда должен (см. lib/routing.sh)
state=$(xray_tmpl_get | routing_state)
want=none
if [[ -r $WARP_ENV ]]; then
  if is_true "${WARP_GOOGLE:-1}"; then want=google-warp; else want=gemini-warp; fi
fi
_routing_refresh() {
  local ob='' rc=0
  [[ -r $WARP_ENV ]] && { ob=$(warp_outbound_json) || ob=''; }
  if [[ -n $ob ]]; then
    warp_health || rc=$?
    if [[ $rc != 0 ]]; then
      warn "WARP сейчас не проходит проверку (${WARP_HEALTH_DETAIL:-код $rc}) — маршрутизацию не трогаю, иначе Google перестанет открываться. Сначала: xui-warp diag / xui-warp rotate"
      return 1
    fi
  fi
  # BLOCK_RU не задан в config.env → сохраняем то, что уже стоит на сервере
  if [[ -z ${BLOCK_RU:-} ]]; then
    BLOCK_RU=$(xray_tmpl_get | jq -r '[.routing.rules[]? | select(.outboundTag=="blocked" and (((.ip // []) | index("geoip:ru")) != null))] | if length > 0 then 1 else 0 end' 2>/dev/null || true)
    BLOCK_RU=${BLOCK_RU:-1}
  fi
  routing_apply "$ob"
}
if [[ $want == none ]]; then
  info "WARP не настроен (нет $WARP_ENV) — Gemini идёт напрямую, менять нечего"
elif [[ $state == "$want" ]]; then
  case $state in
    google-warp) ok "Gemini и вся сессия Google идут через WARP, YouTube — напрямую" ;;
    gemini-warp) ok "Через WARP идёт только Gemini (WARP_GOOGLE=0)" ;;
  esac
elif [[ $ROUTING == 1 ]]; then
  _routing_refresh && RESTARTED=1
else
  case $state in
    gemini-warp) warn "Через WARP идёт только Gemini, а вход в аккаунт Google — с IP VPS. Отсюда «необычный трафик» в Gemini (на странице два IP через ≠). Исправить: bash update-tools.sh --routing" ;;
    gemini-direct) warn "Gemini идёт мимо WARP. Проверь: xui-warp diag, затем bash update-tools.sh --routing" ;;
    google-warp) warn "Через WARP идёт весь Google, а в config.env WARP_GOOGLE=0. Вернуть только Gemini: bash update-tools.sh --routing" ;;
    *) warn "Правила Gemini в шаблоне Xray нет. Добавить: bash update-tools.sh --routing" ;;
  esac
fi

if [[ $RESTARTED == 1 ]]; then
  ok "Готово. Проверка: bash $DIR/selfcheck.sh"
else
  ok "Готово. x-ui не перезапускался. Проверка: bash $DIR/selfcheck.sh"
fi
