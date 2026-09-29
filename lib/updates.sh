# shellcheck shell=bash
# lib/updates.sh — автоматические обновления безопасности Ubuntu/Debian.
# Ставит только security-патчи, чистит неиспользуемые пакеты и старые ядра.

updates_setup() {
  is_true "${AUTO_UPDATES:-1}" || { info "Автообновления безопасности отключены (AUTO_UPDATES=0)"; return 0; }
  export DEBIAN_FRONTEND=noninteractive
  local apt=(apt-get -o DPkg::Lock::Timeout=600 -yq)
  "${apt[@]}" install unattended-upgrades update-notifier-common >/dev/null 2>&1 \
    || { warn "Не установил unattended-upgrades — пропускаю автообновления"; return 0; }

  cat >/etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
// Управляется xui-bootstrap: только security-обновления.
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
EOF

  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  # проверка конфигурации (не критично, если dry-run недоступен)
  if unattended-upgrade --dry-run --debug >/dev/null 2>&1; then
    ok "Автообновления безопасности включены (только *-security, чистка пакетов и ядер)"
  else
    ok "Автообновления безопасности настроены (dry-run проверить не удалось — не критично)"
  fi
}
