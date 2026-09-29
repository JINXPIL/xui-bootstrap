# 🚀 xui-bootstrap

[![CI](https://github.com/JINXPIL/xui-bootstrap/actions/workflows/ci.yml/badge.svg)](https://github.com/JINXPIL/xui-bootstrap/actions/workflows/ci.yml)
[![Shell](https://img.shields.io/badge/bash-5.x-121011?logo=gnubash&logoColor=white)](#)
[![Panel](https://img.shields.io/badge/3x--ui-API-blue)](https://github.com/MHSanaei/3x-ui)

One-command deployment of the **3x-ui** panel on a fresh VPS (**Ubuntu 22.04/24.04**, **Debian 11/12**) with **every modern protocol working out of the box**, DDoS protection and smart routing.

> 🇷🇺 Русская версия: [README.md](README.md)

---

## 💡 Why

3x-ui **does not open firewall ports itself**. Spin up Hysteria2 or TUIC in the UI and it times out because UFW is closed — that's exactly why "only VLESS XHTTP/gRPC/WS used to work".

`xui-bootstrap` fixes this at the root: the **`xui-fw-sync`** daemon reads the panel's inbound list via API every 2 minutes and opens exactly the ports needed (TCP/UDP by protocol and transport), closing ports of deleted inbounds. Add a protocol in the panel — it just starts working.

---

## ✨ Features

### 🔐 All modern protocols at once
`AUTO_INBOUNDS` provisions the full stack, each with fresh keys and its own port:

| Protocol | Transport | Port | Type |
| :--- | :--- | :---: | :---: |
| VLESS Reality Vision | TCP + XTLS-Vision | 443 | TCP |
| VLESS Reality XHTTP | xhttp | 2053 | TCP |
| VLESS Reality gRPC | grpc | 2087 | TCP |
| Trojan Reality Vision | TCP + XTLS-Vision | 2083 | TCP |
| Shadowsocks-2022 | tcp+udp | 2095 | TCP/UDP |
| Hysteria2 | QUIC | 2096 | UDP |
| TUIC v5 | QUIC | 2097 | UDP |

All secrets (UUID, x25519, shortId, passwords, SS keys) are auto-generated — Reality keys come from Xray itself via the API so the format always matches the core. Hysteria2/TUIC get a self-signed cert and clients receive its **SHA-256 pin** in the link — no `allowInsecure`.

### 🌐 Smart routing (fixes Gemini & AliExpress)
* **Gemini / Google AI → WARP.** Google blocks datacenter IPs, so Gemini "loaded forever". The script registers **WARP (Cloudflare)** and routes Google AI through a clean IP.
* **AliExpress → VPS direct.** `aliexpress.ru` was caught by `BLOCK_RU` and blackholed (endless loading). Now it has its own direct rule.
* **BLOCK_RU** still drops `geoip:ru` and `.ru/.su/.рф` server-side.

Rules are idempotent — re-runs never duplicate them or break your manual rules.

### 🛡️ DDoS protection
A dedicated **nftables `xui_ddos`** table (priority −150, before UFW): SYN-flood, junk TCP flags (NULL/XMAS), ICMP-flood protection, and auto-ban of brute-force on SSH/panel. Proxy traffic — including Hysteria2/TUIC UDP — is **deliberately not rate-limited**. Plus `sysctl` hardening (syncookies, backlogs, `rp_filter`, larger conntrack, high-throughput buffers).

### 🎭 Masking
* **Reality** — donor auto-validation (TLS 1.3 + H2) and ASN comparison.
* **Self-steal** — your domain, an Nginx decoy site and a Let's Encrypt certificate.

### 🔒 Secure by default
UFW (panel closed to the internet, SSH-tunnel access), fail2ban for SSH and the panel, optional key-only login, panel bound to `127.0.0.1`.

---

## ⚡ Quick start

**From your machine (recommended):**
```bash
git clone https://github.com/JINXPIL/xui-bootstrap.git && cd xui-bootstrap
cp config.example.env config.env && nano config.env   # at minimum: REALITY_SNI
./deploy.sh root@SERVER_IP
```

**On the server:**
```bash
git clone https://github.com/JINXPIL/xui-bootstrap.git && cd xui-bootstrap
cp config.example.env config.env && nano config.env
chmod +x bootstrap.sh && ./bootstrap.sh
```

On completion the terminal and `/root/xui-result.txt` (mode `600`) contain the panel credentials, the SSH-tunnel command and ready `vless://` / `hysteria2://` / `tuic://` links.

---

## ⚙️ Key `config.env` options

| Variable | Default | Description |
| :--- | :---: | :--- |
| `MASK_MODE` | `reality` | `reality` or `selfsteal` |
| `REALITY_SNI` | `vk.com` | Donor domain (TLS 1.3 + H2) |
| `AUTO_INBOUNDS` | *(full set)* | Which protocols to provision |
| `BLOCK_RU` | `1` | Drop RU traffic server-side |
| `ENABLE_WARP` | `1` | WARP for Gemini/Google AI |
| `ENABLE_DDOS` | `1` | nftables anti-DDoS |
| `ENABLE_BBR` | `1` | TCP BBR + fq |
| `PANEL_PUBLIC` | `0` | `0` — panel via SSH tunnel |
| `SSH_KEYS_ONLY` | `0` | `1` — key-only SSH login |

---

## 🌍 On "whitelist" networks

When an ISP only allows a domestic whitelist, circumvention happens on the **client** via TURN/WebRTC tunnels. Ready client profiles and a curated tool list (csqtt, olcrtc, vk-turn-proxy) live in my [flclash-converter](https://github.com/JINXPIL/flclash-converter) project. On the server side, `xui-bootstrap` keeps this workable: QUIC/UDP protocols (Hysteria2/TUIC) are available immediately, and reputation-sensitive services go through WARP.

---

## 🧪 Development

```bash
shellcheck -x bootstrap.sh lib/*.sh bin/xui-fw-sync
bash tests/validate.sh
```
CI runs shellcheck, shfmt and these checks on every push/PR.

## 📄 License

MIT.
