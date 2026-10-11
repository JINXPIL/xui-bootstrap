#!/usr/bin/env bash
# tests/ssl_test.sh — поведенческие тесты продления сертификата (без сети).
#   • reloadcmd под /bin/sh (как его исполняет acme.sh): SIGHUP получает только
#     главный процесс x-ui, дочерний «xray» остаётся жив; при MainPID=0 — рестарт;
#   • правка конфига acme.sh (интервал и дата продления);
#   • повторное использование действующего серта, разбор SAN.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v openssl >/dev/null && command -v python3 >/dev/null || { echo "ssl_test: нужны openssl, python3 — пропуск"; exit 0; }
T=$(mktemp -d); trap 'pkill -KILL -f "$T/" 2>/dev/null; rm -rf "$T"' EXIT
fail=0
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '\033[31mFAIL\033[0m %s\n' "$*"; fail=1; }
# shellcheck source=/dev/null
. "$ROOT/lib/common.sh"
# shellcheck source=/dev/null
. "$ROOT/lib/ssl.sh"

echo "== reloadcmd: SIGHUP только главному процессу x-ui =="
# «x-ui»: ловит HUP; его «xray»-потомок от HUP умер бы (как Go без обработчика)
cat >"$T/fake-xui.sh" <<'EOF'
#!/usr/bin/env bash
trap 'echo hup >>"$1/xui.hup"' HUP
bash -c 'sleep 300' "$1/fake-xray" </dev/null >/dev/null 2>&1 &
echo $! >"$1/xray.pid"
while :; do sleep 0.2; done
EOF
bash "$T/fake-xui.sh" "$T" </dev/null >/dev/null 2>&1 & XUI=$!
for _ in $(seq 1 50); do [[ -s $T/xray.pid ]] && break; sleep 0.1; done
XRAY=$(cat "$T/xray.pid")
mkdir -p "$T/bin"
printf '#!/bin/sh\ncase "$*" in *MainPID*) echo "${FAKE_MAINPID:-0}";; *restart*) echo restart >>"%s/restarts";; esac\n' "$T" >"$T/bin/systemctl"
chmod +x "$T/bin/systemctl"
PATH="$T/bin:$PATH" FAKE_MAINPID=$XUI sh -c "$XUI_ACME_RELOADCMD"
sleep 0.6
[[ -s $T/xui.hup ]] && pass "x-ui получил SIGHUP (панель и подписка перечитают серт)" || bad "x-ui не получил SIGHUP"
kill -0 "$XRAY" 2>/dev/null && pass "дочерний xray жив — клиенты не рвутся" || bad "xray убит сигналом"
[[ ! -e $T/restarts ]] && pass "рестарта x-ui не было" || bad "лишний рестарт x-ui"
PATH="$T/bin:$PATH" FAKE_MAINPID=0 sh -c "$XUI_ACME_RELOADCMD"
[[ $(cat "$T/restarts" 2>/dev/null) == restart ]] && pass "MainPID=0 → безопасный рестарт, а не kill -HUP 0" || bad "MainPID=0 обработан неверно"
kill -KILL "$XUI" "$XRAY" 2>/dev/null; wait "$XUI" 2>/dev/null

echo "== конфиг acme.sh: интервал продления =="
export HOME="$T/home"; mkdir -p "$HOME/.acme.sh/203.0.113.7_ecc"
conf="$HOME/.acme.sh/203.0.113.7_ecc/203.0.113.7.conf"
printf "Le_Domain='203.0.113.7'\nLe_CertCreateTime='1760000000'\nLe_RenewalDays='6'\nLe_NextRenewTime='1760432000'\nLe_ReloadCmd='x'\n" >"$conf"
_acme_tune_renewal 203.0.113.7 4
grep -q "^Le_RenewalDays='4'$" "$conf" && pass "Le_RenewalDays 6 → 4" || bad "RenewalDays: $(grep RenewalDays "$conf")"
[[ $(sed -n "s/^Le_NextRenewTime='\(.*\)'/\1/p" "$conf") == $((1760000000 + 3 * 86400)) ]] \
  && pass "ближайшее продление — через 3 сут после выпуска (было 5)" || bad "NextRenewTime: $(grep NextRenewTime "$conf")"
grep -q "^Le_ReloadCmd='x'$" "$conf" && pass "прочие ключи acme.sh не тронуты" || bad "конфиг acme.sh повреждён"

echo "== повторное использование серта и разбор SAN =="
mk() { openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$T/$1.key" -out "$T/$1.pem" \
         -days "$2" -subj "/CN=$3" -addext "subjectAltName=$4" 2>/dev/null; }
mk ip 7 203.0.113.7 IP:203.0.113.7
mk old 1 203.0.113.7 IP:203.0.113.7
mk dom 60 vpn.example.com DNS:vpn.example.com
_le_cert_reusable "$T/ip.pem" 203.0.113.7 && pass "действующий IP-серт (7 сут) переиспользуется — без --force перевыпуска" || bad "IP-серт не переиспользован"
_le_cert_reusable "$T/old.pem" 203.0.113.7 && bad "серт, истекающий < 48 ч, нельзя переиспользовать" || pass "серт, истекающий < 48 ч, перевыпускается"
_le_cert_reusable "$T/ip.pem" 198.51.100.1 && bad "серт на другой IP принят" || pass "серт на другой IP не принимается"
id=$(openssl x509 -in "$T/dom.pem" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^[[:space:]]*\(IP Address\|DNS\):[[:space:]]*//p' | head -n1)
[[ $id == vpn.example.com ]] && pass "SAN домена разобран: $id" || bad "SAN домена: «$id»"
id=$(openssl x509 -in "$T/ip.pem" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^[[:space:]]*\(IP Address\|DNS\):[[:space:]]*//p' | head -n1)
[[ $id == 203.0.113.7 ]] && pass "SAN IP разобран: $id" || bad "SAN IP: «$id»"

echo
[[ $fail == 0 ]] && { echo "SSL: ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ"; exit 0; } || { echo "SSL: ЕСТЬ ОШИБКИ"; exit 1; }
