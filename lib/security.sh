# shellcheck shell=bash
# lib/security.sh — SSH-порты, fail2ban (SSH + панель), опциональный вход по ключу.

# security_ssh_ports — печатает список SSH-портов (по одному в строке).
security_ssh_ports() {
  {
    sshd -T 2>/dev/null | awk '$1=="port"{print $2}'
    [[ -n ${SSH_CONNECTION:-} ]] && echo "${SSH_CONNECTION##* }"
  } | sort -un | grep -E '^[0-9]+$' || echo 22
}

# _f2b_backend — systemd-бэкенд нужен python3-systemd; без него fail2ban
# не стартует («Failed to initialize any backend»). Тогда — auto (auth.log).
_f2b_backend() {
  python3 -c 'import systemd.journal' >/dev/null 2>&1 && echo systemd || echo auto
}

# security_fail2ban SSH_PORTS[] — джейлы fail2ban для SSH и (если открыта) панели.
security_fail2ban() {
  local -n _ssh=$1
  local ports; ports=$(IFS=,; echo "${_ssh[*]}")
  local backend; backend=$(_f2b_backend)

  # текущий администратор (SSH IP) в исключения, чтобы не забанить себя
  local ignore="127.0.0.1/8 ::1"
  [[ -n ${ADMIN_IP:-} ]] && ignore="$ignore $ADMIN_IP"

  install -d -m 755 /etc/fail2ban/jail.d
  # mode=aggressive ловит и «мусорные» попытки (kex/preauth, неверные ключи);
  # bantime.increment — повторный бан растёт: 1ч → 2ч → 4ч … до недели.
  cat >/etc/fail2ban/jail.d/xui-sshd.local <<EOF
[sshd]
enabled  = true
backend  = $backend
mode     = aggressive
port     = $ports
maxretry = 3
findtime = 10m
bantime  = 1h
bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 1w
ignoreip = $ignore
EOF

  # Джейл панели 3x-ui. С 3.9 панель пишет в журнал x-ui.service строки вида
  #   WARNING - failed login: username="…", IP="1.2.3.4", reason="…"
  rm -f /etc/fail2ban/jail.d/xui-panel.local
  if is_true "${PANEL_PUBLIC:-0}" && [[ $backend == systemd ]]; then
    cat >/etc/fail2ban/filter.d/xui-panel.conf <<'EOF'
[Definition]
failregex = failed login: .*IP="<HOST>"
ignoreregex =
journalmatch = _SYSTEMD_UNIT=x-ui.service
EOF
    cat >/etc/fail2ban/jail.d/xui-panel.local <<EOF
[xui-panel]
enabled  = true
backend  = systemd
filter   = xui-panel
port     = ${PANEL_PORT:-2053}
maxretry = 5
findtime = 10m
bantime  = 2h
bantime.increment = true
ignoreip = $ignore
EOF
  fi

  systemctl enable fail2ban >/dev/null 2>&1 || true
  if systemctl restart fail2ban 2>/dev/null && sleep 2 && fail2ban-client ping >/dev/null 2>&1; then
    ok "fail2ban: SSH (бэкенд $backend, прогрессивный бан)$( [[ -e /etc/fail2ban/jail.d/xui-panel.local ]] && echo ' и панель')"
  else
    warn "fail2ban не поднялся — проверь: journalctl -u fail2ban -n 30"
  fi
}

# security_ssh_keys_only — при SSH_KEYS_ONLY=1 оставляет вход только по ключу.
# Файл 00-… читается раньше 50-cloud-init.conf, а sshd берёт ПЕРВОЕ значение,
# поэтому облачный «PasswordAuthentication yes» его не перебьёт. После reload
# проверяем фактическую конфигурацию через `sshd -T`.
security_ssh_keys_only() {
  is_true "${SSH_KEYS_ONLY:-0}" || return 0
  if ! grep -qE '^(ssh-(ed25519|rsa)|ecdsa-sha2-|sk-)' /root/.ssh/authorized_keys 2>/dev/null; then
    warn "В /root/.ssh/authorized_keys нет ключей — вход по паролю НЕ отключаю (иначе потеряешь доступ)"
    return 0
  fi
  local f=/etc/ssh/sshd_config.d/00-xui.conf
  install -d -m 755 /etc/ssh/sshd_config.d
  cat >"$f" <<'EOF'
# xui-bootstrap: вход только по ключу
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 20
EOF
  if ! sshd -t 2>/dev/null; then
    rm -f "$f"; warn "sshd -t не прошёл — отключение пароля откатил"; return 0
  fi
  systemctl reload ssh 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
  if [[ $(sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2}') == no ]]; then
    ok "SSH: вход только по ключу (пароль выключен, MaxAuthTries 3)"
  else
    warn "SSH: пароль всё ещё разрешён — что-то перекрывает настройку: grep -ri passwordauth /etc/ssh/"
  fi
}
