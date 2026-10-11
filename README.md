# 🚀 xui-bootstrap

[![CI](https://github.com/JINXPIL/xui-bootstrap/actions/workflows/ci.yml/badge.svg)](https://github.com/JINXPIL/xui-bootstrap/actions/workflows/ci.yml)
[![Shell](https://img.shields.io/badge/bash-5.x-121011?logo=gnubash&logoColor=white)](#)
[![Panel](https://img.shields.io/badge/3x--ui-API-blue)](https://github.com/MHSanaei/3x-ui)

Автоматическое развёртывание панели **3x-ui** на чистом VPS (**Ubuntu 22.04/24.04**, **Debian 11/12**) со **всем набором передовых протоколов, которые работают сразу**, защитой от DDoS и умной маршрутизацией.

Одна команда — и на сервере: маскировка Reality, набор передовых протоколов (VLESS Vision/XHTTP/gRPC, Trojan, Shadowsocks-2022, Hysteria2; TUIC опционально), открытые под них порты, доверенный SSL Let's Encrypt, анти-DDoS на nftables, WARP для Gemini с ротацией IP, рабочий AliExpress и автообновления безопасности.

> 🇬🇧 English version: [README.en.md](README.en.md)

---

## 💡 Почему это нужно

3x-ui **не открывает порты в фаерволе сам**. Поднимаешь в UI Hysteria2 или TUIC — а он уходит в таймаут, потому что UFW закрыт. Раньше «работали только VLESS XHTTP/gRPC/WS», а остальное отваливалось именно поэтому.

`xui-bootstrap` это чинит на корню: демон **`xui-fw-sync`** каждые 2 минуты читает список инбаундов через API панели и открывает ровно нужные порты (TCP/UDP по протоколу и транспорту), а порты удалённых инбаундов закрывает. Добавляешь протокол в панели — он начинает работать сам, без ручной возни с фаерволом.

---

## ✨ Что внутри

### 🔐 Передовые протоколы — рабочий набор под ТСПУ
Каждый протокол поднимается со свежими ключами и своим портом. Дефолтный набор `AUTO_INBOUNDS` подобран под Крым/РФ 2026 — то, что лучше всего переживает ТСПУ:

| Протокол | Транспорт | Порт | Тип | В дефолте |
| :--- | :--- | :---: | :---: | :---: |
| VLESS Reality gRPC | grpc | 443 | TCP | ✅ |
| VLESS Reality XHTTP | xhttp | 2053 | TCP | ✅ |
| Hysteria2 | QUIC | 443 | UDP | ✅ |
| VLESS Reality Vision | TCP + XTLS-Vision | 8443 | TCP | — |
| Trojan Reality | TCP + Reality | 2083 | TCP | — |
| Shadowsocks-2022 | tcp+udp | 2095 | TCP/UDP | — |
| TUIC v5 | QUIC | 2097 | UDP | — |
| VLESS WS-TLS *(selfsteal)* | ws | 8444 | TCP | — |

gRPC (TCP 443) и Hysteria2 (UDP 443) делят один порт 443 — маскировка под обычный HTTPS/QUIC. Любой протокол не из дефолта включается добавлением его имени в `AUTO_INBOUNDS`.

Ключи (UUID, x25519, shortId, пароли, SS-ключи) генерируются автоматически **локальным бинарником `xray`** (не через API панели) — формат гарантированно совпадает с версией ядра. Для Hysteria2 берётся доверенный LE-сертификат (или самоподписанный с **SHA-256 pin**, если LE недоступен).

### 🔐 Доверенный SSL (Let's Encrypt)
Клиенты (FlClash, Happ) отвергают самоподписанные серты. При `SSL_MODE=letsencrypt` (по умолчанию) скрипт через **acme.sh** выпускает валидный сертификат — обычный 90-дневный при заданном `DOMAIN` или на IP (профиль `shortlived` ~6 дней) — и ставит его на панель, подписку и QUIC-инбаунды. Авто-продление включается автоматически (крон acme.sh + systemd-таймер, `reloadcmd` перезапускает x-ui). Если выпуск не удался (нет свободного порта 80, rate-limit) — безопасный откат на самоподписанный.

### 🌐 Умная маршрутизация (лечит Gemini и AliExpress)
* **Gemini / Google AI → WARP.** Google блокирует IP дата-центров, поэтому Gemini «вечно грузился». Скрипт регистрирует **WARP** напрямую в Cloudflare (без API панели), строит нативный wireguard-outbound с `reserved`-байтами и пишет его в `xrayTemplateConfig` через SQLite. Правило глобальное (без привязки к `user`), `routing.domainStrategy = IPIfNonMatch`.
* **Проверка здоровья без самовредительства.** Таймер `xui-warp` раз в 6 ч проверяет путь в две стадии (временный локальный xray, маршрутизация хоста не трогается): сначала сам туннель (`1.1.1.1/cdn-cgi/trace` → `warp=on`), потом Google — с ретраями и ожиданием готовности порта. Дальше по ситуации:
  * туннель жив, Google отвечает → ничего не делает;
  * туннель не поднимается → подбирает UDP-порт эндпоинта (2408 → 500 → 4500 → 1701); если ни один не работает — **панель не перезапускает** (смена IP тут бесполезна);
  * туннель жив, Google блокирует → регистрирует кандидатов, проверяет каждого и подменяет WARP **только проверенно рабочим**.

  x-ui перезапускается лишь при реальном улучшении — каждый рестарт рвёт подключения всех клиентов. Подробная диагностика — `xui-warp diag`.
* **Запасной выход через официальный клиент.** Если на сервере стоит `warp-svc` (Cloudflare WARP, протокол MASQUE) в proxy-режиме, `xui-warp use-svc` переводит Gemini на него, `xui-warp use-wg` — обратно.
* **AliExpress → прямой выход VPS.** `aliexpress.ru` попадал под `BLOCK_RU` и уходил в blackhole. Теперь для него отдельное правило — идёт напрямую.
* **BLOCK_RU** режет `geoip:ru` и `.ru/.su/.рф` на стороне сервера.

Правила идемпотентны: повторный запуск не плодит дубли и не ломает ваши ручные правила.

### 🛡️ Защита от DDoS
Отдельная таблица **nftables `xui_ddos`** (priority −150, до UFW): защита от SYN-флуда, мусорных TCP-флагов (NULL/XMAS), ICMP-флуда. IP текущего SSH-администратора попадает в whitelist (nft + fail2ban), а гвардия перебора — **мягкий rate-limit только на SSH, без бана всего IP** (браузер на неслушающий порт больше не рвёт вашу сессию). Прокси-трафик, включая UDP Hysteria2, по объёму не режется. Плюс хардениг `sysctl`.

### 🔄 Автообновления: ОС, geodata и (опц.) ядро Xray
* **Security-патчи ОС** — `unattended-upgrades` ставит только `*-security`, чистит неиспользуемые пакеты и старые ядра (`AUTO_UPDATES=1`).
* **Geodata (geoip/geosite)** — таймер `xui-geodata` раз в неделю обновляет списки через штатный API панели. Свежие списки РФ и обходных доменов = меньше промахов маршрутизации («то работает, то нет»). Безопасно, **включено по умолчанию** (`AUTO_UPDATE_GEODATA=1`): ядро и инбаунды не трогаются.
* **Ядро Xray** — таймер `xui-core` раз в неделю обновляет ядро до последнего релиза GitHub **с проверкой запуска и автооткатом** на прежнюю версию, плюс защита от случайного даунгрейда. **Выключено по умолчанию** (`AUTO_UPDATE_CORE=0`), и это осознанно: автопроверка ловит только падение ядра, но **не** ловит регрессию Reality (ядро стартует, а часть клиентов молча не коннектится — как было в 26.9.x). Включать — когда готов проверить подключение после апдейта.

Всё это делает один скрипт **`xui-update`** (`geodata` / `core` / `all`), его же можно запускать вручную.

### 🎭 Маскировка
* **Reality** — с автовалидацией донора (TLS 1.3 + H2 через cURL) и сравнением ASN донора и VPS.
* **Self-steal** — свой домен, сайт-заглушка в Nginx и сертификат Let’s Encrypt.

### 🔒 Безопасность из коробки
UFW (панель закрыта наружу, доступ через SSH-туннель), fail2ban для SSH (режим `aggressive`, прогрессивный бан 1 ч → до недели) и панели (читает формат логов 3x-ui 3.9 из журнала), опциональный вход только по ключу (`SSH_KEYS_ONLY=1`: пароль выключен, root только по ключу, `MaxAuthTries 3`; результат проверяется через `sshd -T`, облачный `50-cloud-init.conf` не перебивает), доверенный или самоподписанный HTTPS панели.

У каждого скрипта свой API-токен панели (`xui-bootstrap`, `xui-fw-sync`, `xui-update`, `xui-selfcheck` — видны в «Настройки → API-токены»): в 3x-ui ≥ 3.9 `-getApiToken` перевыпускает токен по имени и отзывает прежний, так что общий токен ломал бы соседние скрипты на лету.

> TUIC по умолчанию выключен (нестабилен на части VPS — сайдкар `tuic-server`); QUIC закрывает Hysteria2. Включается добавлением `tuic` в `AUTO_INBOUNDS`.

---

## ⚡ Быстрый старт

**Вариант A — с локальной машины (рекомендуется):**
```bash
git clone https://github.com/JINXPIL/xui-bootstrap.git && cd xui-bootstrap
cp config.example.env config.env && nano config.env   # минимум — REALITY_SNI
./deploy.sh root@IP_СЕРВЕРА
```

**Вариант B — прямо на сервере:**
```bash
git clone https://github.com/JINXPIL/xui-bootstrap.git && cd xui-bootstrap
cp config.example.env config.env && nano config.env
chmod +x bootstrap.sh && ./bootstrap.sh
```

**Обновить уже развёрнутый сервер** (демоны, проверки, fail2ban — без переустановки, инбаунды/ключи/WARP не трогаются, x-ui не перезапускается):
```bash
cd xui-bootstrap && git pull && bash update-tools.sh
```

По завершении в терминале и в `/root/xui-result.txt` (права `600`) — логин/пароль панели, команда SSH-туннеля и готовые `vless://` / `hysteria2://` / `tuic://` ссылки.

---

## ⚙️ Основные параметры `config.env`

| Переменная | По умолчанию | Описание |
| :--- | :---: | :--- |
| `MASK_MODE` | `reality` | `reality` или `selfsteal` |
| `REALITY_SNI` | `vk.com` | Домен-донор (TLS 1.3 + H2) |
| `SSL_MODE` | `letsencrypt` | `letsencrypt` (доверенный) или `self-signed` |
| `DOMAIN` | — | Домен для 90-дневного LE (иначе LE на IP) |
| `AUTO_INBOUNDS` | *(набор без tuic)* | Какие протоколы поднять |
| `BLOCK_RU` | `1` | Резать RU-трафик на сервере |
| `ENABLE_WARP` | `1` | WARP для Gemini/Google AI + ротация IP |
| `ENABLE_DDOS` | `1` | Анти-DDoS на nftables |
| `AUTO_UPDATES` | `1` | Security-автообновления Ubuntu |
| `AUTO_UPDATE_GEODATA` | `1` | Еженедельное обновление geoip/geosite |
| `AUTO_UPDATE_CORE` | `0` | Еженедельное обновление ядра Xray (с откатом) |
| `ENABLE_BBR` | `1` | TCP BBR + fq |
| `PANEL_PUBLIC` | `0` | `0` — панель через SSH-туннель |
| `SSH_KEYS_ONLY` | `0` | `1` — только вход по ключу |

Полный список — в [`config.example.env`](config.example.env).

---

## 📁 Структура

```text
xui-bootstrap/
├── bootstrap.sh            # оркестратор
├── deploy.sh               # доставка на VPS одной командой
├── update-tools.sh         # обновить демоны на развёрнутом сервере
├── selfcheck.sh            # диагностика сервера (только чтение)
├── config.example.env      # конфигурация
├── lib/                    # модули (preflight/system/security/mask/xui/keys/inbounds/routing/warp/firewall/autoupdate)
├── bin/xui-fw-sync         # демон синхронизации фаервола с панелью
├── bin/xui-warp            # проверка WARP, подбор порта/IP, diag, use-svc
├── bin/xui-update          # обновление geodata и ядра Xray (с откатом)
├── clients/mihomo.example.yaml # готовый клиентский конфиг (FlClash/Clash Verge)
├── inbounds/*.json.example # шаблоны инбаундов всех протоколов
├── systemd/                # unit + timer для xui-fw-sync
├── nftables/               # шаблон анти-DDoS таблицы
├── tests/validate.sh       # оффлайн-проверки (JSON/routing/nft/обновления)
└── .github/workflows/ci.yml
```

---

## 🔐 Доступ к панели (по умолчанию — только туннель)

```bash
ssh -N -L 2222:127.0.0.1:<ПОРТ_ПАНЕЛИ> root@<IP>
# затем в браузере: http://127.0.0.1:2222/<webBasePath>/
```

---

## 🔧 Управление (на сервере)

```bash
# Обновления вручную
xui-update geodata            # обновить списки geoip/geosite сейчас
xui-update core               # обновить ядро Xray сейчас (с проверкой и откатом)

# Включить/выключить авто-обновление ядра без переустановки
systemctl enable --now xui-core.timer     # включить
systemctl disable --now xui-core.timer    # выключить

# Что и когда сработает, журналы
systemctl list-timers 'xui-*'
journalctl -u xui-geodata -u xui-core -n 50 --no-pager

# WARP (Gemini/Google AI)
xui-warp diag                 # диагностика: туннель, порты, warp-svc, DNS — ничего не меняет
xui-warp rotate               # сменить WARP-IP (кандидат проверяется до применения)
xui-warp use-svc 40000        # гнать Gemini через warp-svc (официальный клиент, proxy-режим)
xui-warp use-wg               # вернуться на встроенный WireGuard

# Диагностика всего сервера одной командой
bash selfcheck.sh
```

---

## 🌍 Про «белые списки»

Когда провайдер пускает только на «белый список» отечественных endpoint’ов, обход делается на **клиенте** через TURN/WebRTC-туннели (инкапсуляция в легитимные медиапотоки). Готовые клиентские профили и подборка инструментов (csqtt, olcrtc, vk-turn-proxy) — в моём проекте [flclash-converter](https://github.com/JINXPIL/flclash-converter). Со стороны сервера `xui-bootstrap` держит эту связку рабочей: QUIC/UDP-протоколы (Hysteria2/TUIC) сразу доступны, а критичные к репутации сервисы идут через WARP.

---

## 🧪 Разработка

```bash
shellcheck -x bootstrap.sh lib/*.sh bin/xui-fw-sync
bash tests/validate.sh    # оффлайн: JSON-шаблоны, маршрутизация, nft -c
```
CI (GitHub Actions) прогоняет shellcheck, shfmt и эти проверки на каждый push/PR.

---

## 🛡️ Безопасность

* `config.env` и `inbounds/*.json` — в `.gitignore`, ключи в репозиторий не попадут.
* Отчёт и выгрузки хранятся на VPS с правами `600`.

## 📄 Лицензия

MIT.
