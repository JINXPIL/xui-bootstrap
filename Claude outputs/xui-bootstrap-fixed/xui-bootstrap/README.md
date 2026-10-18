# 🚀 xui-bootstrap

[![CI](https://github.com/JINXPIL/xui-bootstrap/actions/workflows/ci.yml/badge.svg)](https://github.com/JINXPIL/xui-bootstrap/actions/workflows/ci.yml)
[![Shell](https://img.shields.io/badge/bash-5.x-121011?logo=gnubash&logoColor=white)](#)
[![Panel](https://img.shields.io/badge/3x--ui-API-blue)](https://github.com/MHSanaei/3x-ui)

Автоматическое развёртывание панели **3x-ui** на чистом VPS (**Ubuntu 22.04/24.04**, **Debian 11/12**) со **всем набором передовых протоколов, которые работают сразу**, защитой от DDoS и умной маршрутизацией.

Одна команда — и на сервере: маскировка Reality, семь протоколов (VLESS Vision/XHTTP/gRPC, Trojan, Shadowsocks-2022, Hysteria2, TUIC), открытые под них порты, анти-DDoS на nftables, WARP для Gemini и рабочий AliExpress.

> 🇬🇧 English version: [README.en.md](README.en.md)

---

## 💡 Почему это нужно

3x-ui **не открывает порты в фаерволе сам**. Поднимаешь в UI Hysteria2 или TUIC — а он уходит в таймаут, потому что UFW закрыт. Раньше «работали только VLESS XHTTP/gRPC/WS», а остальное отваливалось именно поэтому.

`xui-bootstrap` это чинит на корню: демон **`xui-fw-sync`** каждые 2 минуты читает список инбаундов через API панели и открывает ровно нужные порты (TCP/UDP по протоколу и транспорту), а порты удалённых инбаундов закрывает. Добавляешь протокол в панели — он начинает работать сам, без ручной возни с фаерволом.

---

## ✨ Что внутри

### 🔐 Все передовые протоколы сразу
Из коробки поднимается набор `AUTO_INBOUNDS` — каждый со свежими ключами и своим портом:

| Протокол | Транспорт | Порт | Порт-тип |
| :--- | :--- | :---: | :---: |
| VLESS Reality Vision | TCP + XTLS-Vision | 443 | TCP |
| VLESS Reality XHTTP | xhttp | 2053 | TCP |
| VLESS Reality gRPC | grpc | 2087 | TCP |
| Trojan Reality Vision | TCP + XTLS-Vision | 2083 | TCP |
| Shadowsocks-2022 | tcp+udp | 2095 | TCP/UDP |
| Hysteria2 | QUIC | 2096 | UDP |
| TUIC v5 | QUIC | 2097 | UDP |

Ключи (UUID, x25519, shortId, пароли, SS-ключи) генерируются автоматически — ключи Reality берутся у самого Xray нужной версии через API, поэтому формат гарантированно совпадает. Для Hysteria2/TUIC создаётся самоподписанный сертификат, а клиентам в ссылку кладётся его **SHA-256 pin** — без `allowInsecure`.

### 🌐 Умная маршрутизация (лечит Gemini и AliExpress)
* **Gemini / Google AI → WARP.** Google блокирует IP дата-центров, поэтому Gemini «вечно грузился». Скрипт регистрирует **WARP (Cloudflare)** и гонит Google AI через чистый IP.
* **AliExpress → прямой выход VPS.** `aliexpress.ru` попадал под `BLOCK_RU` и уходил в blackhole (бесконечная загрузка). Теперь для него отдельное правило — идёт напрямую.
* **BLOCK_RU** по-прежнему режет `geoip:ru` и `.ru/.su/.рф` на стороне сервера (защита от деанона).

Правила идемпотентны: повторный запуск не плодит дубли и не ломает ваши ручные правила.

### 🛡️ Защита от DDoS
Отдельная таблица **nftables `xui_ddos`** (priority −150, до UFW): защита от SYN-флуда, мусорных TCP-флагов (NULL/XMAS), ICMP-флуда, автобан перебора на SSH/панель (в динамический чёрный список на час). Прокси-трафик, включая UDP Hysteria2/TUIC, **намеренно не режется по объёму**. Плюс хардениг `sysctl`: syncookies, backlog’и, `rp_filter`, увеличенный conntrack, буферы под высокую пропускную способность.

### 🎭 Маскировка
* **Reality** — с автовалидацией донора (TLS 1.3 + H2 через cURL) и сравнением ASN донора и VPS.
* **Self-steal** — свой домен, сайт-заглушка в Nginx и сертификат Let’s Encrypt.

### 🔒 Безопасность из коробки
UFW (панель закрыта наружу, доступ через SSH-туннель), fail2ban для SSH и панели, опциональный вход только по ключу, панель прибита к `127.0.0.1`.

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

По завершении в терминале и в `/root/xui-result.txt` (права `600`) — логин/пароль панели, команда SSH-туннеля и готовые `vless://` / `hysteria2://` / `tuic://` ссылки.

---

## ⚙️ Основные параметры `config.env`

| Переменная | По умолчанию | Описание |
| :--- | :---: | :--- |
| `MASK_MODE` | `reality` | `reality` или `selfsteal` |
| `REALITY_SNI` | `vk.com` | Домен-донор (TLS 1.3 + H2) |
| `AUTO_INBOUNDS` | *(весь набор)* | Какие протоколы поднять |
| `BLOCK_RU` | `1` | Резать RU-трафик на сервере |
| `ENABLE_WARP` | `1` | WARP для Gemini/Google AI |
| `ENABLE_DDOS` | `1` | Анти-DDoS на nftables |
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
├── config.example.env      # конфигурация
├── lib/                    # модули (preflight/system/security/mask/xui/keys/inbounds/routing/firewall)
├── bin/xui-fw-sync         # демон синхронизации фаервола с панелью
├── inbounds/*.json.example # шаблоны инбаундов всех протоколов
├── systemd/                # unit + timer для xui-fw-sync
├── nftables/               # шаблон анти-DDoS таблицы
├── tests/validate.sh       # оффлайн-проверки (JSON/routing/nft)
└── .github/workflows/ci.yml
```

---

## 🔐 Доступ к панели (по умолчанию — только туннель)

```bash
ssh -N -L 2222:127.0.0.1:<ПОРТ_ПАНЕЛИ> root@<IP>
# затем в браузере: http://127.0.0.1:2222/<webBasePath>/
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
