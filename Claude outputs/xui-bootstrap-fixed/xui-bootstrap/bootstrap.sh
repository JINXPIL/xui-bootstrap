#!/usr/bin/env bash
# xui-bootstrap — 3x-ui на чистом VPS: маскировка, весь набор передовых
# протоколов сразу, анти-DDoS, авто-синхронизация фаервола и умная
# маршрутизация (Gemini/AliExpress/RU). Идемпотентно, безопасно, без ручной
# возни в UI.
set -Eeuo pipefail
shopt -u patsub_replacement 2>/dev/null || true

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULT=/root/xui-result.txt
exec > >(tee -a /var/log/xui-bootstrap.log) 2>&1

# --- модули ---
for m in common preflight system security mask xui keys inbounds routing firewall; do
  # shellcheck source=/dev/null
  . "$DIR/lib/$m.sh"
done

trap 'die "Упал на строке $LINENO: $BASH_COMMAND"' ERR

# ---------- 0. проверки, конфиг, пакеты ----------
step "Проверки окружения и установка пакетов"
preflight_checks
preflight_packages

# ---------- 1. сетевой стек ----------
step "Настройка сетевого стека"
system_tune

# ---------- 2. SSH-порты, фаервол, fail2ban ----------
step "Базовая безопасность"
mapfile -t SSH_PORTS < <(security_ssh_ports)
(( ${#SSH_PORTS[@]} )) || SSH_PORTS=(22)

# IP текущего SSH-администратора — в whitelist фаервола и fail2ban,
# чтобы анти-DDoS/бан не оборвал собственную сессию.
ADMIN_IP=$(awk '{print $1}' <<<"${SSH_CONNECTION:-${SSH_CLIENT:-}}")
[[ ${ADMIN_IP:-} =~ ^[0-9a-fA-F:.]+$ ]] || ADMIN_IP=''
export ADMIN_IP
[[ -n $ADMIN_IP ]] && info "SSH-администратор: $ADMIN_IP (добавлен в исключения)"
firewall_base SSH_PORTS
security_fail2ban SSH_PORTS
security_ssh_keys_only

# ---------- 3. маскировка ----------
step "Маскировка трафика"
mask_setup

# ---------- 4. установка панели и API ----------
step "Установка 3x-ui"
xui_install
xui_bind_panel
export XUI_API_READY=1
xui_install_xray "${XRAY_VERSION:-}"

# ---------- 5. анти-DDoS ----------
step "Защита от DDoS"
firewall_ddos SSH_PORTS

# ---------- 6. инбаунды: весь набор протоколов ----------
step "Импорт инбаундов (все передовые протоколы)"
EXIST=$(api GET panel/api/inbounds/list 2>/dev/null | jq -r '.obj[]?.port // empty' 2>/dev/null || true)
inbounds_provision "$DIR/inbounds" "$EXIST"

# ---------- 7. открыть порты + демон авто-синхронизации ----------
step "Фаервол: порты инбаундов и авто-синхронизация"
firewall_open_ports "$(join_csv "${INB_TCP_PORTS[@]}")" "$(join_csv "${INB_UDP_PORTS[@]}")"
firewall_install_sync

# ---------- 8. маршрутизация (Gemini/AliExpress/RU) ----------
step "Маршрутизация"
WARP_OB=""
if is_true "${ENABLE_WARP:-1}"; then
  info "Регистрирую WARP (Cloudflare) для сервисов, блокирующих IP хостингов…"
  WARP_OB=$(routing_register_warp || true)
  [[ -n $WARP_OB ]] && ok "WARP-аутбаунд готов" || warn "WARP недоступен — Gemini пойдёт напрямую"
fi
routing_apply "$WARP_OB" || warn "Маршрутизация применена частично"
systemctl restart x-ui

# ---------- 9. итоговый отчёт ----------
step "Готово — собираю отчёт"
IFS=$'\t' read -r XUI_USER XUI_PASS < <(xui_credentials) || true
XRAY_VER=$(xui_xray_version)
LINKS=$(api GET panel/api/inbounds/allLinks -H "Host: $PUBLIC_HOST" 2>/dev/null | jq -r '.obj[]?' || true)
{
  echo "=== $PUBLIC_HOST ($SERVER_IP) — $(date -u '+%F %H:%M') UTC ==="
  echo "Маска: $MASK_MODE | SNI: $SNI | dest: $DEST | Xray: ${XRAY_VER:-?}"
  echo "Протоколы: ${AUTO_INBOUNDS:-reality-vision xhttp-reality grpc-reality trojan-reality ss2022 hysteria2 tuic}"
  echo "TCP: ${INB_TCP_PORTS[*]:-—} | UDP: ${INB_UDP_PORTS[*]:-—}"
  echo "Анти-DDoS: $( is_true "${ENABLE_DDOS:-1}" && echo включён || echo выключен) | WARP: $( [[ -n $WARP_OB ]] && echo активен || echo нет)"
  echo
  if is_true "${PANEL_PUBLIC:-0}"; then
    echo "Панель (прямой доступ):"
    echo "  $PANEL_SCHEME://$PUBLIC_HOST:$PANEL_PORT$WBP   ${XUI_USER:+логин: $XUI_USER  пароль: $XUI_PASS}"
  else
    echo "Панель (только через SSH-туннель):"
    echo "  ssh -N -L 2222:127.0.0.1:$PANEL_PORT -p ${SSH_PORTS[0]} root@$SERVER_IP"
    echo "  $PANEL_SCHEME://127.0.0.1:2222$WBP   ${XUI_USER:+логин: $XUI_USER  пароль: $XUI_PASS}"
  fi
  [[ ${PANEL_SCHEME:-http} == https ]] && echo "  (самоподписанный сертификат — браузер один раз предупредит: «Дополнительно» → «Перейти»)"
  echo; echo "Ссылки для клиентов:"; echo "${LINKS:-(не получил — возьми в панели)}"
} >"$RESULT"; chmod 600 "$RESULT"
cat "$RESULT"
ok "Готово. Отчёт: $RESULT"
