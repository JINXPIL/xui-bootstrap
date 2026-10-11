#!/usr/bin/env bash
# tests/update_test.sh — `xui-update check`: какой релиз берётся для проверки.
# Регрессия с боевого сервера: GitHub «Latest» = v26.3.27 (стабильный), а на
# сервере уже 26.9.30 — проверка тестировала СТАРШЕЕ ядро и писала «обновляться
# можно». Теперь берётся самый новый тег, а даунгрейд не предлагается.
# Без сети: curl/git подменены, «ядро» — скрипт, строго требующий конфиг *.json.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPD=${XUI_UPDATE:-$ROOT/bin/xui-update}
fail=0
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '\033[31mFAIL\033[0m %s\n' "$*"; fail=1; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/fakebin" "$T/xui/bin"

# «ядро»: version → "Xray N"; run -test -c FILE.json → OK (строго *.json); REJECT=тег → отказ
mkx() { # mkx NUM  → печатает скрипт
  cat <<X
#!/bin/sh
case "\$1" in
  version) echo "Xray $1 (fake)";;
  run) f=; while [ \$# -gt 0 ]; do [ "\$1" = -c ] && f=\$2; shift; done
       case "\$f" in *.json) ;; *) echo "Failed to get format of \$f" >&2; exit 23;; esac
       if [ "\${FAKE_REJECT:-}" = "$1" ]; then echo "Failed to start: removed feature" >&2; exit 23; fi
       echo "Configuration OK."; exit 0;;
esac
X
}
mkx 26.9.30 >"$T/xui/bin/xray-linux-amd64"; chmod +x "$T/xui/bin/xray-linux-amd64"
echo '{"inbounds":[]}' >"$T/xui/bin/config.json"

# curl: список релизов / latest / скачивание zip с «ядром» нужной версии
cat >"$T/fakebin/curl" <<'EOF2'
#!/bin/bash
out=; url=
while [ $# -gt 0 ]; do case $1 in -o) out=$2; shift;; https://*) url=$1;; esac; shift; done
echo "$url" >>"$FAKE_LOG"
case $url in
  *"/releases?per_page"*) [ -n "${FAKE_API_DOWN:-}" ] && exit 22; cat "$FAKE_LIST";;
  *"/releases/latest") [ -n "${FAKE_API_DOWN:-}" ] && exit 22; echo '{"tag_name":"v26.3.27"}';;
  *"/releases/download/"*)
     tag=$(sed -E 's#.*/download/([^/]+)/.*#\1#' <<<"$url")
     mkdir -p "$FAKE_TMP/z"; "$FAKE_MKX" "${tag#v}" >"$FAKE_TMP/z/xray"
     python3 -I -c 'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],"w"); z.write(sys.argv[2],"xray")' "$out" "$FAKE_TMP/z/xray";;
  *) exit 22;;
esac
EOF2
chmod +x "$T/fakebin/curl"
# git ls-remote (запасной путь, когда API недоступно)
cat >"$T/fakebin/git" <<'EOF2'
#!/bin/bash
for t in v26.3.27 v26.9.8 v26.9.9 v26.9.30 v26.10.10; do echo "abc	refs/tags/$t"; done
EOF2
chmod +x "$T/fakebin/git"
# mkx доступен fake-curl'у как отдельный скрипт
{ echo '#!/bin/bash'; declare -f mkx; echo 'mkx "$@"'; } >"$T/mkx.sh"; chmod +x "$T/mkx.sh"

list() { # list TAG... → JSON как у GitHub (порядок как у API: по дате, новые первыми)
  local t first=1; printf '['
  for t in "$@"; do ((first)) || printf ','; first=0; printf '{"tag_name":"%s","draft":false,"prerelease":%s}' "$t" "$([[ $t == v26.3.27 ]] && echo false || echo true)"; done
  printf ']'
}
run() { # run ARGS... → вывод xui-update check
  : >"$T/log"
  PATH="$T/fakebin:$PATH" XUI_DIR="$T/xui" XUI_LIB="$ROOT/lib" FAKE_LOG="$T/log" FAKE_LIST="$T/list.json" \
    FAKE_TMP="$T" FAKE_MKX="$T/mkx.sh" bash "$UPD" "$@" 2>&1
}

# 1. «Latest» старее установленного, но есть пре-релиз 26.10.10 → проверяем его
list v26.10.10 v26.9.30 v26.9.9 v26.3.27 >"$T/list.json"
out=$(run check)
grep -q 'Релиз v26.10.10 (26.10.10)' <<<"$out" && pass "check без аргумента берёт самый новый тег (26.10.10, а не «Latest» 26.3.27)" || bad "check взял не тот релиз: $(grep -m2 'Релиз\|НЕ' <<<"$out")"
grep -q 'download/v26.3.27' "$T/log" && bad "скачано старое ядро v26.3.27" || pass "старое ядро v26.3.27 не скачивалось"
grep -q 'Обновить: xui-update core' <<<"$out" && bad "для не-Latest релиза предложено xui-update core" || pass "для не-Latest релиза не обещается xui-update core"
grep -q 'Latest.*v26.3.27' <<<"$out" && pass "пояснение, почему core не ставит эту версию" || bad "нет пояснения про Latest"

# 2. самый новый уже стоит
mkx 26.10.10 >"$T/xui/bin/xray-linux-amd64"
grep -q 'уже установлен' <<<"$(run check)" && pass "та же версия — «уже установлен»" || bad "для той же версии нет сообщения"
mkx 26.9.30 >"$T/xui/bin/xray-linux-amd64"

# 3. всё, что есть, старее установленного → ничего не качаем и не предлагаем
list v26.3.27 v26.2.1 >"$T/list.json"
out=$(run check)
{ grep -q 'не новее установленного' <<<"$out" && ! grep -q 'download/' "$T/log"; } && pass "релизы старее установленного: даунгрейд не предлагается, ничего не скачано" || bad "старый релиз проверяется: $(tail -n2 <<<"$out")"

# 4. явный старый тег — проверка идёт, но с пометкой «даунгрейд»
out=$(run check v26.3.27)
{ grep -q 'даунгрейд' <<<"$out" && ! grep -q 'Обновить: xui-update core' <<<"$out"; } && pass "явный старый тег: проверен, помечен как даунгрейд" || bad "явный старый тег: $(tail -n2 <<<"$out")"

# 5. API недоступно → git ls-remote, сортировка по версии (26.10.10 > 26.9.30)
list v26.3.27 >"$T/list.json"
out=$(FAKE_API_DOWN=1 run check)
grep -q 'Релиз v26.10.10' <<<"$out" && pass "API недоступно: запасной путь через теги, 26.10.10 новее 26.9.x" || bad "запасной путь: $(tail -n3 <<<"$out")"

# 6. новое ядро не принимает конфиг → предупреждение и код возврата 1
list v26.10.10 v26.9.30 >"$T/list.json"
out=$(FAKE_REJECT=26.10.10 run check); rc=$?
{ grep -q 'НЕ примет' <<<"$out" && [[ $rc -eq 1 ]]; } && pass "отказ нового ядра: «НЕ примет», код возврата 1" || bad "отказ ядра не замечен (rc=$rc): $(tail -n2 <<<"$out")"

# 7. текущее ядро проверяется на *.json-копии конфига (регрессия mktemp)
out=$(run check)
grep -q 'конфиг загружается' <<<"$out" && pass "конфиг проверяется на копии *.json" || bad "копия конфига без .json не принята ядром"

echo
[[ $fail == 0 ]] && { echo "UPDATE: ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ"; exit 0; } || { echo "UPDATE: ЕСТЬ ОШИБКИ"; exit 1; }
