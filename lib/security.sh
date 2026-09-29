# shellcheck shell=bash
# lib/security.sh — SSH-порты, fail2ban (SSH + панель), опциональный вход по ключу.

# security_ssh_ports — печатает список SSH-портов (по одному в строке).
security_ssh_ports() {
  {
    sshd -T 2>/dev/null | awk '$1=="port"{print $2}'
    [[ -n ${SSH_CONNECTION:-} ]] && echo "${SSH_CONNECTION##* }"
  } | sort -un | grep -E '^[0-9]+$' || echo 22
}

# security_fail2ban SSH_PORTS[] — джейлы fail2ban для SSH и (если открыта) панели.
security_fail2ban() {
  local -n _ssh=$1
  local ports; ports=$(IFS=,; echo "${_ssh[*]}")

  # текущий администратор (SSH IP) в исключения, чтобы не забанить себя
  local ignore="127.0.0.1/8 ::1"
  [[ -n ${ADMIN_IP:-} ]] && ignore="$ignore $ADMIN_IP"

  install -d -m 755 /etc/fail2ban/jail.d
  cat >/etc/fail2ban/jail.d/xui-sshd.local <<EOF
[sshd]
enabled = true
backend = systemd
port    = $ports
maxretry = 5
findtime = 10m
bantime  = 1h
ignoreip = $ignore
EOF

  # Джейл панели 3x-ui (логи неудачных входов пишет сама панель).
  if is_true "${PANEL_PUBLIC:-0}"; then
    local log=/usr/local/x-ui/access.log
    cat >/etc/fail2ban/filter.d/xui-panel.conf <<'EOF'
[Definition]
failregex = .*"(POST|GET).*login.*" .*from <HOST>.*(fail|invalid|wrong)
            .*Login failed.*from IP: <HOST>
ignoreregex =
EOF
    cat >/etc/fail2ban/jail.d/xui-panel.local <<EOF
[xui-panel]
enabled  = true
port     = ${PANEL_PORT:-2053}
filter   = xui-panel
logpath  = $log
maxretry = 5
findtime = 10m
bantime  = 2h
ignoreip = $ignore
EOF
  fi

  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban 2>/dev/null || warn "fail2ban не поднялся"
  ok "fail2ban: защита SSH$( is_true "${PANEL_PUBLIC:-0}" && echo ' и панели')"
}

# security_ssh_keys_only SSH — при SSH_KEYS_ONLY=1 отключает вход по паролю.
security_ssh_keys_only() {
  is_true "${SSH_KEYS_ONLY:-0}" || return 0
  if [[ ! -s /root/.ssh/authorized_keys ]]; then
    warn "authorized_keys пуст — вход по паролю НЕ отключаю (иначе потеряешь доступ)"
    return 0
  fi
  install -d -m 755 /etc/ssh/sshd_config.d
  printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' >/etc/ssh/sshd_config.d/00-xui.conf
  if sshd -t; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    ok "SSH: вход только по ключу"
  else
    rm -f /etc/ssh/sshd_config.d/00-xui.conf
    warn "sshd -t не прошёл — откатил отключение пароля"
  fi
}
