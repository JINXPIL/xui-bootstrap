#!/usr/bin/env bash
# ============================================================================
#  update-tools.sh — обновить демоны и библиотеки xui-bootstrap на УЖЕ
#  развёрнутом сервере. НЕ трогает инбаунды, ключи, WARP-регистрацию,
#  маршрутизацию и саму панель (x-ui не перезапускается).
#
#    git pull && sudo bash update-tools.sh
# ============================================================================
set -Eeuo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for m in common xui keys warp security autoupdate; do
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

ok "Готово. x-ui не перезапускался. Проверка: bash $DIR/selfcheck.sh"
