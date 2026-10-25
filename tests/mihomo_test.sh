#!/usr/bin/env bash
# tests/mihomo_test.sh — клиентский шаблон clients/mihomo.example.yaml проверяется
# НАСТОЯЩИМ Mihomo (`mihomo -t`): конфиг принимается и в логе нет ошибок
# (например, об удалённых опциях вроде global-client-fingerprint).
# Бинарник: $MIHOMO_BIN, `mihomo` из PATH, либо скачивается при MIHOMO_DOWNLOAD=1.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '\033[31mFAIL\033[0m %s\n' "$*"; fail=1; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

MB=${MIHOMO_BIN:-$(command -v mihomo || true)}
if [[ -z $MB && ${MIHOMO_DOWNLOAD:-0} == 1 ]]; then
  tag=$(git ls-remote --tags --refs https://github.com/MetaCubeX/mihomo.git 2>/dev/null \
        | awk -F/ '{print $NF}' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1)
  [[ -n $tag ]] && curl -fsSL -o "$T/m.gz" "https://github.com/MetaCubeX/mihomo/releases/download/$tag/mihomo-linux-amd64-$tag.gz" \
    && gunzip -f "$T/m.gz" && chmod +x "$T/m" && MB="$T/m"
fi
[[ -n $MB && -x $MB ]] || { echo "mihomo_test: бинарника mihomo нет (MIHOMO_BIN / MIHOMO_DOWNLOAD=1) — пропуск"; exit 0; }
echo "Клиент: $("$MB" -v | head -n1)"

# правдоподобные значения вместо плейсхолдеров (ключ — настоящий x25519 base64url)
PUB=$(python3 -I -c 'import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="))')
sed -e "s/SERVER_IP/203.0.113.10/g; s/REALITY_SNI/vk.com/; s|PUBLIC_KEY|$PUB|g; s/\"SHORT_ID\"/\"0123abcd\"/g" \
    -e "s|XHTTP_PATH|/a1b2|; s/UUID/11111111-1111-1111-1111-111111111111/g; s/H2_PASSWORD/secretpw/; s/CERT_HOST/203.0.113.10/" \
    "$ROOT/clients/mihomo.example.yaml" >"$T/config.yaml"
grep -qE 'SERVER_IP|PUBLIC_KEY|XHTTP_PATH|H2_PASSWORD|CERT_HOST' "$T/config.yaml" && bad "в шаблоне остались незаменённые плейсхолдеры"

out=$(cd "$T" && timeout 120 "$MB" -t -d "$T" -f "$T/config.yaml" 2>&1)
[[ $out == *"test is successful"* ]] && pass "Mihomo принимает шаблон" || bad "Mihomo не принял шаблон: $(tail -n 2 <<<"$out")"
errs=$(grep -E 'level=(error|fatal)' <<<"$out" | sed -E 's/.*msg="?([^"]*)"?$/\1/' | sort -u)
[[ -z $errs ]] && pass "в логе Mihomo нет ошибок (удалённых/неизвестных опций)" || bad "ошибки Mihomo: $errs"

# опциональные прокси (gRPC, WS-TLS) закомментированы — раскомментируем и проверяем тоже
sed -E 's/^  # (- name:|  [a-z])/  \1/' "$T/config.yaml" >"$T/opt.yaml"
nopt=$(grep -cE '^  - name: "(gRPC-Reality|WS-TLS)"' "$T/opt.yaml")
out=$(cd "$T" && timeout 120 "$MB" -t -d "$T" -f "$T/opt.yaml" 2>&1)
if [[ $nopt -eq 2 && $out == *"test is successful"* ]] && ! grep -qE 'level=(error|fatal)' <<<"$out"; then
  pass "опциональные прокси (gRPC, WS-TLS) тоже валидны"
else bad "опциональные прокси ($nopt из 2): $(grep -E 'level=(error|fatal)' <<<"$out" | tail -n 2; tail -n 1 <<<"$out")"; fi

echo
[[ $fail == 0 ]] && { echo "MIHOMO: ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ"; exit 0; } || { echo "MIHOMO: ЕСТЬ ОШИБКИ"; exit 1; }
