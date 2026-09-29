# shellcheck shell=bash
# lib/xui.sh — установка/обновление 3x-ui и доступ к его локальному API.
# Экспортирует: xui_install, xui_bind_panel, api(), а также TOKEN/BASE/PANEL_PORT.

XUI_BIN=${XUI_BIN:-/usr/local/x-ui/x-ui}
XUI_DB=${XUI_DB:-/etc/x-ui/x-ui.db}
XUI_BIN_DIR=${XUI_BIN_DIR:-/usr/local/x-ui/bin}
XUI_INSTALL_URL=${XUI_INSTALL_URL:-https://raw.githubusercontent.com/MHSanaei/3x-ui/main/install.sh}

# xray_tmpl_get — печатает текущий xrayTemplateConfig из БД (надёжнее API).
xray_tmpl_get() {
  python3 - "$XUI_DB" <<'PY' 2>/dev/null
import sqlite3, sys
try:
    c = sqlite3.connect(sys.argv[1]); cur = c.cursor()
    cur.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'")
    r = cur.fetchone(); print(r[0] if r and r[0] else '', end='')
    c.close()
except Exception:
    pass
PY
}

# _xray_default_template — встроенный дефолтный шаблон Xray панели 3x-ui
# (api/stats/policy/metrics + direct/blocked). Используется, когда в свежей БД
# ещё нет ключа xrayTemplateConfig (появляется только после ручного сохранения
# настроек в веб-интерфейсе).
_xray_default_template() {
  cat <<'JSON'
{
  "api": { "services": ["HandlerService","LoggerService","StatsService","RoutingService"], "tag": "api" },
  "inbounds": [{ "listen": "127.0.0.1", "port": 62789, "protocol": "tunnel", "settings": { "rewriteAddress": "127.0.0.1" }, "tag": "api" }],
  "log": { "access": "none", "dnsLog": false, "error": "", "loglevel": "warning", "maskAddress": "" },
  "metrics": { "listen": "127.0.0.1:11111", "tag": "metrics_out" },
  "outbounds": [
    { "protocol": "freedom", "settings": { "finalRules": [ { "action": "block", "ip": ["geoip:private"] }, { "action": "allow" } ] }, "tag": "direct" },
    { "protocol": "blackhole", "settings": {}, "tag": "blocked" }
  ],
  "policy": { "levels": { "0": { "statsUserDownlink": true, "statsUserUplink": true } }, "system": { "statsInboundDownlink": true, "statsInboundUplink": true, "statsOutboundDownlink": false, "statsOutboundUplink": false } },
  "routing": { "domainStrategy": "AsIs", "rules": [
    { "inboundTag": ["api"], "outboundTag": "api", "type": "field" },
    { "ip": ["geoip:private"], "outboundTag": "blocked", "type": "field" },
    { "outboundTag": "blocked", "protocol": ["bittorrent"], "type": "field" }
  ] },
  "stats": {}
}
JSON
}

# xray_tmpl_get_or_default — шаблон из БД → API → дефолт панели → встроенный дефолт.
# Никогда не возвращает пусто, если удалось получить хоть один валидный источник.
xray_tmpl_get_or_default() {
  local t; t=$(xray_tmpl_get)
  if is_json "$t"; then printf '%s' "$t"; return 0; fi
  # API: сохранённый шаблон
  t=$(api POST panel/api/xray/ 2>/dev/null | jq -c '.obj // empty | fromjson? | .xraySetting' 2>/dev/null || true)
  if is_json "$t" && [[ $t != null ]]; then printf '%s' "$t"; return 0; fi
  # API: дефолтный шаблон панели
  t=$(api GET panel/api/xray/getDefaultJsonConfig 2>/dev/null | jq -c '.obj // empty' 2>/dev/null || true)
  if is_json "$t" && [[ $t != null ]]; then printf '%s' "$t"; return 0; fi
  # встроенный дефолт (совпадает с config.json панели)
  _xray_default_template
}

# xray_tmpl_set FILE — записывает xrayTemplateConfig из файла в БД.
# Панель останавливается на время записи, чтобы не затереть изменение при выходе.
xray_tmpl_set() {
  local f="$1"
  [[ -s $f ]] || { warn "xray_tmpl_set: пустой файл"; return 1; }
  is_json "$(cat "$f")" || { warn "xray_tmpl_set: невалидный JSON, не пишу"; return 1; }
  systemctl stop x-ui 2>/dev/null || true
  local ok=1
  python3 - "$XUI_DB" "$f" <<'PY' || ok=0
import sqlite3, sys
db, f = sys.argv[1], sys.argv[2]
v = open(f, encoding='utf-8').read()
c = sqlite3.connect(db); cur = c.cursor()
cur.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'", (v,))
if cur.rowcount == 0:
    cur.execute("INSERT INTO settings(key,value) VALUES('xrayTemplateConfig',?)", (v,))
c.commit(); c.close()
PY
  systemctl start x-ui 2>/dev/null || true
  [[ $ok == 1 ]]
}

# xui_settings_get KEY — одно значение из таблицы settings.
xui_settings_get() {
  python3 - "$XUI_DB" "$1" <<'PY' 2>/dev/null
import sqlite3, sys
try:
    c = sqlite3.connect(sys.argv[1]); cur = c.cursor()
    cur.execute("SELECT value FROM settings WHERE key=?", (sys.argv[2],))
    r = cur.fetchone(); print(r[0] if r and r[0] is not None else '', end='')
    c.close()
except Exception:
    pass
PY
}

# xui_fix_sidecars — сайдкар-бинарники (tuic-server, mtg и т.п.) должны быть +x,
# иначе панель падает с "No such file or directory (os error 2)" при запуске.
xui_fix_sidecars() {
  [[ -d $XUI_BIN_DIR ]] || return 0
  chmod +x "$XUI_BIN_DIR"/tuic-server* "$XUI_BIN_DIR"/mtg* "$XUI_BIN_DIR"/xray-linux-* 2>/dev/null || true
  ok "Права на сайдкар-бинарники (+x) выставлены"
}

# xui_assets_install — кладёт lib/ в /usr/local/share для переиспользования демонами.
xui_assets_install() {
  install -d -m 755 /usr/local/share/xui-bootstrap/lib
  install -m 644 "$DIR"/lib/*.sh /usr/local/share/xui-bootstrap/lib/ 2>/dev/null || true
}

# xui_install — ставит или обновляет 3x-ui до нужной версии (неинтерактивно).
xui_install() {
  local ver="${XUI_VERSION:-}"
  if [[ -x $XUI_BIN ]]; then
    info "Обновляю установленный 3x-ui${ver:+ до $ver}…"
  else
    info "Ставлю 3x-ui ${ver:-latest}…"
  fi
  local tmp; tmp=$(mktemp)
  curl -fsSL "$XUI_INSTALL_URL" -o "$tmp" || die "Не скачал install.sh 3x-ui"
  # install.sh 3x-ui уважает эти переменные в неинтерактивном режиме
  XUI_NONINTERACTIVE=1 XUI_SSL_MODE=none bash "$tmp" ${ver:+"$ver"} </dev/null \
    || die "Установщик 3x-ui завершился с ошибкой"
  rm -f "$tmp"
  [[ -x $XUI_BIN ]] || die "Бинарник x-ui не найден после установки"
  xui_fix_sidecars
}

# _panel_ensure_listen_all — гарантирует, что webListen = 0.0.0.0 (панель наружу).
# CLI-флаг иногда не применяется на существующей БД — тогда правим SQLite напрямую.
_panel_ensure_listen_all() {
  local cur; cur=$("$XUI_BIN" setting -getListen 2>/dev/null | awk '/listenIP:/{print $2}')
  [[ -z $cur || $cur == 0.0.0.0 ]] && return 0   # пусто = все интерфейсы, уже ок
  [[ $cur == 127.* ]] || return 0
  if ! command -v sqlite3 >/dev/null 2>&1; then
    warn "webListen=$cur, а sqlite3 не установлен — панель может остаться на localhost"; return 0
  fi
  systemctl stop x-ui 2>/dev/null || true
  sqlite3 /etc/x-ui/x-ui.db "UPDATE settings SET value='0.0.0.0' WHERE key='webListen';" 2>/dev/null || true
  systemctl start x-ui 2>/dev/null || true
  ok "webListen принудительно выставлен в 0.0.0.0 (через SQLite)"
}

# _panel_port_fallback — порт панели, если 'setting -show' не отдал (install-result.env → SQLite).
_panel_port_fallback() {
  local p=''
  if [[ -r /etc/x-ui/install-result.env ]]; then
    # shellcheck source=/dev/null
    p=$(. /etc/x-ui/install-result.env 2>/dev/null; printf '%s' "${XUI_PANEL_PORT:-}")
  fi
  if [[ -z $p ]] && command -v sqlite3 >/dev/null 2>&1; then
    p=$(sqlite3 /etc/x-ui/x-ui.db "SELECT value FROM settings WHERE key='webPort';" 2>/dev/null || true)
  fi
  printf '%s' "$p"
}

# xui_bind_panel — прибивает панель к нужному интерфейсу и поднимает API-токен.
# Выставляет глобальные TOKEN, BASE, PANEL_PORT, PANEL_SCHEME, WBP.
xui_bind_panel() {
  if is_true "${PANEL_PUBLIC:-0}"; then
    "$XUI_BIN" setting -listenIP 0.0.0.0 >/dev/null 2>&1 || warn "Не смог задать listenIP панели"
    _panel_ensure_listen_all
  else
    "$XUI_BIN" setting -listenIP 127.0.0.1 >/dev/null 2>&1 || warn "Не смог прибить панель к localhost"
  fi

  TOKEN=$("$XUI_BIN" setting -getApiToken -tokenName xui-bootstrap 2>/dev/null | awk '/^apiToken:/{print $2}' || true)
  [[ -n $TOKEN ]] || die "x-ui не выдал API-токен (нужна актуальная версия 3x-ui с поддержкой API-токенов)"

  xui_panel_ssl   # самоподписанный HTTPS для панели (бессрочно)
  systemctl restart x-ui

  local show; show=$("$XUI_BIN" setting -show 2>/dev/null || true)
  PANEL_PORT=$(awk '$1=="port:"{print $2}' <<<"$show")
  [[ -n $PANEL_PORT ]] || PANEL_PORT=$(_panel_port_fallback)
  WBP=$(awk '$1=="webBasePath:"{print $2}' <<<"$show"); WBP="/${WBP#/}"; WBP="${WBP%/}/"
  [[ -n $PANEL_PORT ]] || die "Не смог определить порт панели (ни из 'setting -show', ни из install-result.env)"

  # Публичный доступ — сразу открываем реальный порт панели в UFW, не дожидаясь
  # общего шага фаервола (на случай ошибки на более поздних этапах).
  if is_true "${PANEL_PUBLIC:-0}"; then
    ufw allow "$PANEL_PORT/tcp" comment 'xui-panel' >/dev/null 2>&1 || true
  fi

  # Схему НЕ угадываем по слову «SSL» в выводе (там оно есть и при выключенном
  # TLS). Пробуем http и https напрямую, каждую секунду, пока API не ответит.
  local _ sc
  for _ in $(seq 1 60); do
    for sc in http https; do
      BASE="$sc://127.0.0.1:$PANEL_PORT$WBP"
      if api GET panel/api/server/status 2>/dev/null | jq -e '.success' >/dev/null 2>&1; then
        # shellcheck disable=SC2034  # PANEL_SCHEME/XUI_API_READY читаются в bootstrap.sh/keys.sh/inbounds.sh
        PANEL_SCHEME="$sc"
        # shellcheck disable=SC2034
        XUI_API_READY=1
        ok "API панели отвечает ($sc, порт $PANEL_PORT)"
        return 0
      fi
    done
    sleep 1
  done
  warn "Последние строки журнала x-ui:"
  journalctl -u x-ui -n 15 --no-pager 2>/dev/null | sed 's/^/    /' >&2 || true
  die "API панели не ответило за 60с (порт $PANEL_PORT, путь $WBP)"
}

# xui_panel_ssl — включает HTTPS для панели.
#  • если ssl_setup выдал доверенный Let's Encrypt (LE_OK=1) — ставим его
#    (клиенты примут подписку без ошибок x509);
#  • иначе — бессрочный самоподписанный (браузер предупредит один раз).
# Отключается через PANEL_SSL=0.
xui_panel_ssl() {
  is_true "${PANEL_SSL:-1}" || { info "HTTPS панели отключён (PANEL_SSL=0)"; return 0; }

  # Доверенный LE-сертификат — приоритет (важно для подписок FlClash/Happ).
  if [[ ${LE_OK:-0} == 1 && -s ${LE_CERT:-} && -s ${LE_KEY:-} ]]; then
    if "$XUI_BIN" setting -webCert "$LE_CERT" -webCertKey "$LE_KEY" >/dev/null 2>&1; then
      ok "Панель/подписка: доверенный HTTPS (Let's Encrypt${LE_SNI:+, $LE_SNI})"
      return 0
    fi
    warn "Панель не приняла LE-сертификат — пробую самоподписанный"
  fi

  local dir="${CERT_DIR:-/etc/x-ui-bootstrap}"
  local pub="$dir/panel.pem" key="$dir/panel.key"
  install -d -m 700 "$dir"

  if [[ ! -s $pub || ! -s $key ]]; then
    info "Генерирую бессрочный самоподписанный сертификат для панели…"
    local host="${PUBLIC_HOST:-${SERVER_IP:-127.0.0.1}}" san
    if [[ $host =~ ^[0-9.]+$ ]]; then san="IP:$host"; else san="DNS:$host"; fi
    [[ -n ${SERVER_IP:-} && $SERVER_IP != "$host" ]] && san="$san,IP:$SERVER_IP"
    openssl ecparam -genkey -name prime256v1 -out "$key" 2>/dev/null
    if ! openssl req -new -x509 -key "$key" -out "$pub" -days 3650 \
         -subj "/CN=$host" -addext "subjectAltName=$san" 2>/dev/null; then
      warn "Не смог создать сертификат панели — останется HTTP"; return 0
    fi
    chmod 644 "$pub"; chmod 600 "$key"
  fi

  if "$XUI_BIN" setting -webCert "$pub" -webCertKey "$key" >/dev/null 2>&1; then
    ok "Панель: самоподписанный HTTPS включён (сертификат бессрочный)"
  else
    warn "Панель не приняла сертификат — останется HTTP"
  fi
}

# api METHOD PATH [curl-args...] — вызов локального API панели.
api() {
  local m=$1 p=$2; shift 2
  curl -k -sS --max-time 180 -X "$m" -H "Authorization: Bearer ${TOKEN:-}" "$@" "$BASE$p"
}

# xui_install_xray VERSION — фиксирует версию ядра Xray, если задана.
xui_install_xray() {
  local ver="${1:-}"
  [[ -n $ver ]] || return 0
  if api POST "panel/api/server/installXray/$ver" | jq -e '.success' >/dev/null; then
    ok "Xray → $ver"
  else
    warn "Не удалось поставить Xray $ver — оставляю текущую версию ядра"
  fi
}

# xui_credentials — печатает "USER<TAB>PASS" из install-result (открытый пароль,
# который 3x-ui сохраняет при установке; в самой БД пароль — bcrypt-хеш и
# открытым текстом недоступен). Всегда завершается переводом строки и кодом 0,
# чтобы `read` не падал под set -e.
xui_credentials() {
  local u='' p=''
  if [[ -r /etc/x-ui/install-result.env ]]; then
    # shellcheck source=/dev/null
    u=$(. /etc/x-ui/install-result.env 2>/dev/null; printf '%s' "${XUI_USERNAME:-}")
    # shellcheck source=/dev/null
    p=$(. /etc/x-ui/install-result.env 2>/dev/null; printf '%s' "${XUI_PASSWORD:-}")
  fi
  printf '%s\t%s\n' "$u" "$p"
  return 0
}

# xui_xray_version — версия ядра Xray для отчёта.
xui_xray_version() {
  # бинарник ядра имеет суффикс архитектуры (xray-linux-amd64 и т.п.)
  # shellcheck disable=SC2211
  { /usr/local/x-ui/bin/xray-linux-* version 2>/dev/null || true; } | awk 'NR==1{print $2}'
}
