# MNEBYVPN Nodekit — этап 1: проверка и подготовка нового VPS

**Статус: PREPARE ONLY.** Начало унифицированного комплекта, НЕ рабочий «одна команда — и сервер подключён». Существующие скрипты из scripts/ привязаны к конкретным конфигурациям боевых 89/188 и не являются универсальным установщиком.

## Контракт

- Один JSON: schema_version=1, node_id, роль edge|egress|combined, явный список dns|vpn|sni-proxy|tunnel, TCP/UDP порты и уникальный FQDN.
- preflight: проверяет Debian 12/13 либо Ubuntu 24.04, x86_64/aarch64, свободное место >=5 GiB (проектный порог, а не гарантия емкости), systemd и возможность занять IPv4 порты. Не проверяет IPv6, операторские ограничения/DPI, маршрут с телефона, доступность извне или фактическую работоспособность приложений.
- stage: атомарно готовит только /var/lib/mnebyvpn-nodekit/<node_id>/manifest.json и preflight.json, ограничивая права 0600 и 0700. Не устанавливает ПО и не трогает существующие nginx, CoreDNS, Xray, WireGuard, systemctl, nftables, iptables или DNS-записи.
- Состояние нового узла всегда testing; activation_enabled=false и registration_enabled=false. Даже успешный stage не публикует адрес пользователям и не меняет сервера 89/188.
- Спецификация v1 не содержит секретов. TLS private keys, Reality/WG private keys, личные DNS-профили, пароли и платёжные токены нельзя помещать в Git или логи Actions.
- Отказ при неверной роли, неожиданных полях, пересечении TCP-портов, занятых IPv4 портах и попытке перезаписать уже staged-узел.

## Запуск на новом VPS

Из копии репозитория на новом VPS, после настройки приватного JSON по образцу node-spec.example.json:

    sudo bash nodekit/bootstrap.sh preflight /root/private-node-spec.json
    sudo bash nodekit/bootstrap.sh stage /root/private-node-spec.json

Эти команды ПОКА НЕ устанавливают VPN/DNS/прокси. Пример использует вымышленный домен.

## Следующие обязательные компоненты для настоящего one-command install

1. Пакеты CoreDNS, Xray, WireGuard и nginx с закреплёнными версиями/хэшами; изолированные service units, порты, обратимый способ активации.
2. Подписанный приватный bundle с TLS/Reality/WireGuard идентичностями, персональной DNS policy, SNI strict allowlist и известными upstream. Не допускать публичного неаутентифицированного open proxy.
3. Безопасный контроллер регистрации: planned -> testing -> canary -> verified -> enabled, отзывы и связанные назначения пользователей; никаких записей в production сразу после установки пакетов.
4. Проверка реальных DoT-ответов, TLS/SNI до origin, VPN E2E, прав и expiration, rollback, monitoring из клиентских сетей и сохранение прежних клиентов.
5. Запуск через GitHub Actions или API хостера после покупки нового VPS, проверка бюджета и политики. Создание и биллинг VPS этим v1 не реализованы.

См. docs/mnebydns-safe-config-deployment.md в этом репозитории и https://github.com/grunvald91/Mnebyvpn/blob/main/docs/scale-out-contract.md.

## Подготовка через GitHub Actions (без ручного SSH)

После слияния ветки доступен ручной workflow **MNEBYVPN prepare NEW VPS (no production changes)**. Он не запускается по push или pull_request. Для первого VPS требуется отдельно настроить в GitHub Actions secrets:

- MNEBYVPN_NEW_NODE_SSH_KEY — специальный приватный SSH-ключ только для нового VPS (не ключи старых узлов).
- MNEBYVPN_NEW_NODE_KNOWN_HOSTS — заранее проверенный pinned SSH host key для этого нового VPS; workflow не выполняет автоматическое доверие незнакомому ключу.

Запуск в Actions -> Run workflow: host, node_id, advertise_host, mode=preflight|stage. Текущий шаблон готовит только роль combined с портами DoT TCP/853, VPN TCP/2053, SNI TCP/443 и tunnel UDP/51820. Прочие роли и порты поддерживает JSON CLI, но не этот первый workflow. Для запуска требуется root SSH на новом VPS и Python 3; работающие серверы не переписываются. Вывод workflow не означает, что хотя бы одна служба установлена или клиенты переключены.

Для следующего узла нельзя переиспользовать SSH ключи и идентичности VPN предыдущего узла. Позднее нужна регистрация одноразовым enrollment-токеном вместо общего GitHub secret.
