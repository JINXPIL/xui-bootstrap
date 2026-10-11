# shellcheck shell=bash
# lib/mask.sh — маскировка: Reality (валидация донора) и selfsteal (свой сайт+ACME).
# Экспортирует SNI, DEST, PUBLIC_HOST, SERVER_IP (используются в других модулях).
# shellcheck disable=SC2034  # переменные читаются в bootstrap.sh/inbounds.sh

# mask_detect_ip — публичный IP сервера.
mask_detect_ip() {
  SERVER_IP=$(curl -4fsS --max-time 6 https://api.ipify.org 2>/dev/null \
    || ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}' || true)
  [[ -n ${SERVER_IP:-} ]] || die "Не определил IP сервера — задай SERVER_ADDR в config.env"
}

_asn_of() {
  [[ ${1:-} =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 0
  dig +short +time=3 +tries=1 TXT "${BASH_REMATCH[4]}.${BASH_REMATCH[3]}.${BASH_REMATCH[2]}.${BASH_REMATCH[1]}.origin.asn.cymru.com" 2>/dev/null \
    | tr -d '"' | awk -F'|' 'NR==1{split($1,a," "); print a[1]}' || true
}

# mask_setup — настраивает маскировку в зависимости от MASK_MODE.
mask_setup() {
  mask_detect_ip
  case "${MASK_MODE:-reality}" in
    reality)
      [[ -n ${REALITY_SNI:-} ]] || die "Задай REALITY_SNI в config.env"
      SNI=$REALITY_SNI
      DEST=${REALITY_DEST:-$REALITY_SNI:443}
      PUBLIC_HOST=${SERVER_ADDR:-$SERVER_IP}
      _mask_validate_reality
      ;;
    selfsteal)
      [[ -n ${DOMAIN:-} ]] || die "Задай DOMAIN в config.env (режим selfsteal)"
      SNI=$DOMAIN
      DEST=127.0.0.1:8443
      PUBLIC_HOST=${SERVER_ADDR:-$DOMAIN}
      _mask_setup_selfsteal
      ;;
    *) die "MASK_MODE должен быть reality или selfsteal" ;;
  esac
  ok "Маскировка: ${MASK_MODE} | SNI: $SNI | dest: $DEST"
}

_mask_validate_reality() {
  local v; v=$(curl -s -o /dev/null --max-time 10 --tlsv1.3 --http2 -w '%{http_version}' "https://$SNI/" 2>/dev/null || true)
  if [[ $v == 2 ]]; then ok "Донор $SNI: TLS 1.3 + h2"; else warn "Донор $SNI не дал TLS1.3+h2 ($v) — Reality с ним может не работать, смени REALITY_SNI"; fi
  local a1 a2; a1=$(_asn_of "$SERVER_IP"); a2=$(_asn_of "$(getent ahostsv4 "$SNI" 2>/dev/null | awk 'NR==1{print $1}' || true)")
  if [[ -n $a1 && -n $a2 ]]; then
    [[ $a1 == "$a2" ]] && ok "Донор в той же AS$a1, что и VPS" || warn "Донор в AS$a2, VPS в AS$a1 — лучше донор из подсети своего хостера"
  fi
}

_mask_setup_selfsteal() {
  require nginx certbot
  local ips; ips=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)
  [[ " $ips " == *" $SERVER_IP "* ]] || die "$DOMAIN → [${ips:-нет}], а сервер $SERVER_IP. Поправь A-запись (в Cloudflare — серое облако)"

  local web=/var/www/decoy; mkdir -p "$web"
  if [[ -d $DIR/site ]]; then cp -r "$DIR/site/." "$web/"
  elif [[ ! -f $web/index.html ]]; then
    local t=${DOMAIN%%.*}
    cat >"$web/index.html" <<EOC
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${t^}</title><style>body{font:16px/1.6 system-ui,sans-serif;max-width:640px;margin:10vh auto;padding:0 20px;color:#222}
footer{margin-top:4em;color:#888;font-size:14px}@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}}</style></head>
<body><h1>${t^}</h1><p>Personal notes, small tools and experiments. The new version of the site is on its way.</p>
<footer>&copy; $(date +%Y) ${DOMAIN}</footer></body></html>
EOC
  fi

  rm -f /etc/nginx/sites-enabled/default
  cat >/etc/nginx/conf.d/decoy.conf <<EOC
server {
    listen 80 default_server; listen [::]:80 default_server;
    server_tokens off;
    location /.well-known/acme-challenge/ { root $web; }
    location / { return 301 https://$DOMAIN\$request_uri; }
}
EOC
  nginx -t -q || die "nginx: битый конфиг (HTTP)"
  systemctl enable nginx >/dev/null 2>&1 || true; systemctl restart nginx

  if [[ ! -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]]; then
    local em=(--register-unsafely-without-email)
    [[ -n ${ACME_EMAIL:-} ]] && em=(-m "$ACME_EMAIL")
    certbot certonly --webroot -w "$web" -d "$DOMAIN" --agree-tos --non-interactive "${em[@]}" --deploy-hook "systemctl reload nginx" \
      || die "certbot не выпустил сертификат для $DOMAIN"
  fi

  cat >>/etc/nginx/conf.d/decoy.conf <<EOC

server {
    listen 127.0.0.1:8443 ssl;
    http2 on;
    server_name $DOMAIN;
    server_tokens off;
    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    root $web; index index.html;
    location / { try_files \$uri \$uri/ =404; }
}
EOC
  nginx -t -q || die "nginx: битый конфиг (HTTPS)"
  systemctl reload nginx
  # для ws-tls инбаундов дадим xray сертификат домена
  CERT_PUB=/etc/letsencrypt/live/$DOMAIN/fullchain.pem
  CERT_KEY=/etc/letsencrypt/live/$DOMAIN/privkey.pem
  ok "Self-steal: $DOMAIN → свой сайт на 127.0.0.1:8443"
}
