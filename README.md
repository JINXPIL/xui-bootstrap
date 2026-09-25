# xui-bootstrap

Автоматизированный скрипт развёртывания 3x-ui на чистом VPS с Debian/Ubuntu.

## Возможности
- Веб-интерфейс изолирован на 127.0.0.1 (вход только через SSH-туннель).
- Маскировка: Reality и Self-steal (Nginx + Let's Encrypt).
- Безопасность: UFW (default deny), fail2ban, BBR и синхронизация времени NTP.
- Блокировка RU-трафика на стороне сервера.
- Автоматический импорт подготовленных инбаундов.

## Быстрый старт
1. Скопируйте конфиг: cp config.example.env config.env
2. Подготовьте шаблон: cp inbounds/vless-reality.json.example inbounds/vless-reality.json
3. Запустите установку: ./deploy.sh root@<IP_СЕРВЕРА> [SSH_ПОРТ]
