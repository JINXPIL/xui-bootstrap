# shellcheck shell=bash
# lib/common.sh — общие помощники: логирование, проверки, утилиты.
# Подключается всеми модулями. Не запускается напрямую.

# --- цветной вывод (отключается, если stderr не терминал или NO_COLOR) ---
# ВАЖНО: все логи идут в stderr, а не в stdout. Иначе строка лога, напечатанная
# внутри $( ... )-подстановки (например, генерация сертификата в _render),
# попадёт в захватываемые данные и сломает jq.
if [[ -t 2 && -z ${NO_COLOR:-} ]]; then
  _C_OK=$'\033[32m'; _C_INFO=$'\033[36m'; _C_WARN=$'\033[33m'; _C_ERR=$'\033[31m'; _C_DIM=$'\033[2m'; _C_RST=$'\033[0m'
else
  _C_OK=''; _C_INFO=''; _C_WARN=''; _C_ERR=''; _C_DIM=''; _C_RST=''
fi

ok()   { printf '%s[ok]%s %s\n'   "$_C_OK"   "$_C_RST" "$*" >&2; }
info() { printf '%s[..]%s %s\n'   "$_C_INFO" "$_C_RST" "$*" >&2; }
warn() { printf '%s[!!]%s %s\n'   "$_C_WARN" "$_C_RST" "$*" >&2; }
step() { printf '\n%s==>%s %s\n'  "$_C_INFO" "$_C_RST" "$*" >&2; }
die()  { printf '%s[xx]%s %s\n'   "$_C_ERR"  "$_C_RST" "$*" >&2; exit 1; }
dbg()  { [[ -n ${DEBUG:-} ]] && printf '%s[dbg]%s %s\n' "$_C_DIM" "$_C_RST" "$*" >&2 || true; }

# require CMD... — падает, если команды нет в PATH
require() {
  local miss=()
  local c
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || miss+=("$c"); done
  ((${#miss[@]} == 0)) || die "Не хватает утилит: ${miss[*]}"
}

# is_true VAL — «1/true/yes/on» → успех
is_true() {
  case "${1,,}" in 1 | true | yes | on | y) return 0 ;; *) return 1 ;; esac
}

# trim STRING
trim() { local s="$*"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

# retry N SLEEP CMD... — повторить команду до N раз с паузой SLEEP сек
retry() {
  local n=$1 s=$2; shift 2
  local i
  for ((i = 1; i <= n; i++)); do
    if "$@"; then return 0; fi
    ((i < n)) && sleep "$s"
  done
  return 1
}

# valid_port N
valid_port() { [[ $1 =~ ^[0-9]+$ ]] && ((1 <= $1 && $1 <= 65535)); }

# free_port [START] — вернуть свободный TCP-порт (пытается со START, потом рандом)
free_port() {
  local p="${1:-}"
  local tries=0
  while ((tries < 50)); do
    if [[ -z $p ]]; then p=$((RANDOM % 20000 + 20000)); fi
    if ! { ss -Hltn "sport = :$p" 2>/dev/null | grep -q . || ss -Hlun "sport = :$p" 2>/dev/null | grep -q .; }; then
      printf '%s' "$p"; return 0
    fi
    p=''; ((tries++))
  done
  die "Не нашёл свободный порт"
}

# json_get FILE FILTER — безопасный jq -r с проверкой
json_get() { jq -r "$2" "$1" 2>/dev/null; }

# join_csv ELEMENTS... — склеить аргументы через запятую
join_csv() {
  local out='' e
  for e in "$@"; do out+="${out:+,}$e"; done
  printf '%s' "$out"
}
