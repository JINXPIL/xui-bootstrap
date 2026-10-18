#!/usr/bin/env bash
# Развернуть на новом VPS одной командой:  ./deploy.sh root@IP [ssh-порт]
set -euo pipefail
T=${1:?"Использование: ./deploy.sh root@IP [ssh-порт]"}; PORT=${2:-22}
cd "$(dirname "$0")"
R=/root/.xui-bootstrap
O=(-p "$PORT" -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15)

[[ -f config.env ]] || { echo "Сначала: cp config.example.env config.env && nano config.env"; exit 1; }

if command -v ssh-copy-id >/dev/null; then ssh-copy-id "${O[@]}" "$T" 2>/dev/null || true; fi

# что кладём на сервер: скрипты, модули, шаблоны, systemd/nft, демон, конфиг
files=(bootstrap.sh config.env lib bin inbounds systemd nftables)
[[ -d site ]] && files+=(site)

tar -czf - "${files[@]}" \
  | ssh "${O[@]}" "$T" "rm -rf $R && mkdir -p $R && chmod 700 $R && tar -xzf - -C $R && chmod +x $R/bootstrap.sh $R/bin/* 2>/dev/null || true"
ssh -t "${O[@]}" "$T" "bash $R/bootstrap.sh; rc=\$?; rm -rf $R; exit \$rc"

mkdir -p servers
scp -P "$PORT" -o StrictHostKeyChecking=accept-new -q "$T:/root/xui-result.txt" "servers/${T#*@}.txt" 2>/dev/null || true
echo "Готово: servers/${T#*@}.txt"
