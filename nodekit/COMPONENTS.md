# Nodekit: установка компонентов (этап 2)

На новом изолированном VPS с Ubuntu 24.04 (x86_64 / aarch64) Nodekit устанавливает Xray, CoreDNS, Nginx и WireGuard tools. Это пока НЕ готовая клиентская сеть: слушатели, сертификаты, WG peer, VPN-клиенты, DNS policy, регистрация и подписки не активируются.

## Предпосылки

- preflight -> stage -> identity завершены для одного уникального node_id.
- Запуск по паролю из Actions пока разрешён ТОЛЬКО для тестового VPS 217.11.167.91; действующие узлы 89.125.90.101 и 188.120.254.223 защищены allowlist.
- Ubuntu 24.04 с root-доступом; nginx должен быть неактивен, а /usr/sbin/policy-rc.d — отсутствовать (чужую политику не перезаписываем).
- Доступ через HTTPS к GitHub Release Assets и официальным Ubuntu APT репозиториям.

## Сценарий через GitHub Actions

Workflow: MNEBYVPN NEW VPS bootstrap (old production untouched).

Ввод: host=217.11.167.91; node_id=fi-test-01; advertise_host=fi-test.mnebyvpn.site.

0. mode=prepare_all: единым запуском (с возможностью безопасного возобновления) выполняет stage → identity → components_install → vpn_stage для нового или частично подготовленного узла. Перед повторным запуском сверяет существующую спецификацию и никогда не перегенерирует ключи.
1. mode=components_check: проверить состояние нового узла без изменений.
2. mode=components_install: скачать и установить Xray v26.11.9, CoreDNS v1.15.0 по закреплённым SHA-256 архивов, поставить через Ubuntu APT nginx, libnginx-mod-stream, wireguard-tools. Временный policy-rc.d запрещает запуски во время APT; nginx затем остановлен и отключён от автозапуска.
3. mode=vpn_stage_auto: взять SHA-256 установленного Xray из локального манифеста и независимо проверить бинарник через существующий vpn_stage.py, создать неактивную конфигурацию REALITY без клиентов.

Манифест: /var/lib/mnebyvpn-nodekit/<node_id>/components-manifest.json, права 0600.
Повторная установка не перезаписывает существующие файлы: сверяет хеши и завершается, если они различаются.
Режимы supervisor_install/supervisor_canary по-прежнему требуют дополнительного публичного ключа контроллера и подтверждённого хэша Xray.

## Проверяемые первоисточники фиксированных выпусков

- Xray-core [v26.11.9](https://github.com/XTLS/Xray-core/releases/tag/v26.11.9):
  - amd64 Xray-linux-64.zip SHA-256: b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82
  - arm64 Xray-linux-arm64-v8a.zip SHA-256: 64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be
- CoreDNS [v1.15.0](https://github.com/coredns/coredns/releases/tag/v1.15.0):
  - amd64 archive SHA-256: 2495c5b8f3fab6d0a336c397f1227b75406d86e6ec7125744a29df9e936ab8cd
  - arm64 archive SHA-256: 73a5bf107c9791d57741ccd59ad138ab00bcd5bb3f62e2e28c999f5c047334a4

Ubuntu APT использует подписанные пакеты с актуальными security updates; конкретные установленные версии сохраняются в манифест.

## Важные ограничения

APT изменяет базу пакетов нового VPS; при прерывании возможна частичная установка (проверить dpkg --audit). Скрипт не касается firewall, сетевых маршрутов и настроек боевых серверов. Успех компонентов означает лишь готовность бинарников, НЕ готовность подключения клиента.

Дальше необходимы: TLS/DoT-сертификат, персональная DNS policy, безопасный Nginx SNI proxy, WireGuard peers и маршрутизация, регистрация/отзыв в контроллере, независимые тесты VPN/DNS/TLS и только затем публикация в подписках с правильной страной.

SSH через StrictHostKeyChecking=accept-new с временным known_hosts пока использует TOFU и уязвим к подмене первоначального соединения. Для тиражирования необходим закреплённый host key и отдельные секреты каждого VPS.
