#!/usr/bin/env bash
# Новый VPS одной командой:  ./deploy.sh root@IP [порт]
set -euo pipefail
T=${1:?"Использование: ./deploy.sh root@IP [порт]"}; PORT=${2:-22}
cd "$(dirname "$0")"
R=/root/.xui-bootstrap
O=(-p "$PORT" -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15)
[[ -f config.env ]] || { echo "Сначала: cp config.example.env config.env"; exit 1; }
compgen -G "inbounds/*.json" >/dev/null || { echo "Положи шаблоны в inbounds/*.json"; exit 1; }

if command -v ssh-copy-id >/dev/null; then ssh-copy-id "${O[@]}" "$T" || true; fi

extra=(); if [[ -d site ]]; then extra=(site); fi
tar -czf - bootstrap.sh config.env inbounds ${extra[@]+"${extra[@]}"} \
  | ssh "${O[@]}" "$T" "rm -rf $R && mkdir -p $R && chmod 700 $R && tar -xzf - -C $R"
ssh -t "${O[@]}" "$T" "bash $R/bootstrap.sh; rc=\$?; rm -rf $R; exit \$rc"
mkdir -p servers
scp -P "$PORT" -o StrictHostKeyChecking=accept-new -q "$T:/root/xui-result.txt" "servers/${T#*@}.txt"
echo "Готово: servers/${T#*@}.txt"
