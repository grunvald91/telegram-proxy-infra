# MNEBYVPN Nodekit — подписанные клиенты AmneziaWG 3.1

## Назначение

Универсальный `Nodekit Fleet Bootstrap` подготавливает будущие VPS независимо от страны. Дополнительно `awg_peer_grants.py`, `awg-lease-signer.mjs` и `install_awg_watchdog.py` реализуют **контракт доступа**, но не публикуют клиента в тарифах и не создают ему закрытый ключ.

### Подпись и защита

Trusted central controller должен **перед подписанием** прочитать в своей БД живое `ACTIVE` VPN entitlement, его `revision`, срок окончания, идентификатор зарегистрированного узла, проверить разрешённую выдачу нового peer и IP. Библиотека `nodekit/awg-lease-signer.mjs` только формирует Ed25519 подпись. Сам подписывающий закрытый ключ хранится исключительно у контроллера, не у GitHub, не на VPS, не у агента. Совпадающий протокол на VPS принимает только root-only JSON с точными полями:

`nodeId, op, entitlementId, revision, peerPublicKey, clientIpv4, expiresAt, issuedAt, nonce, signature`

- `op=grant`: только для установленного узла, `expiresAt` в будущем не дальше 60 минут, ревизия строго растёт.
- `op=revoke`: тот же entitlement, ключ и IP, новая ревизия, `expiresAt=null`; нельзя выдать доступ старой командой.
- Адрес клиента внутри тестового туннеля `10.73.91.2…254/32`; локальная подсеть статична **только для одного финского тестового узла**. Для нескольких стран потребуется IPAM/подсеть из общего контроллера до реальной публикации. Одинаковые публичные ключи и IPv4 повторно не назначаются.
- Публичный ключ клиента создаётся клиентом; приватный клиентский ключ никогда не попадает в Nodekit. Редкая ключевая ротация проходит отдельным одобренным процессом.
- Ed25519 подписанный payload точно сериализован как `["MNEBYVPN_AWG_LEASE_V1",...]`, подписывается node-specific, URL-безопасная подпись. Принимаются только команды с `issuedAt` в пределах 45 секунд.
- Сервер использует root-only `<node-dir>/controller-access.spki` — **тот же заранее одобренный контроллер**, что у Xray supervisor. Отсутствие ключа запрещает управление клиентами.

### Автоматический отзыв

Сначала `awg_watchdog_install` устанавливает root-only peer supervisor и systemd unit **без его запуска/включения**. Только после регистрации контроллера и контрольных проверок оператор может отдельно включить watchdog (ни одна стадия Fleet Bootstrap этого не делает).

При работающем unit каждые 2 секунды сверяется защищённый локальный реестр и реальное состояние AmneziaWG. Истёкшие гранты исчезают из живых peers, даже если API/контроллер недоступен. Если реестр повреждён, бинарник отличается, syncconf вернул ошибку или ключи не совпали, доступ не должен оставаться открыт: код вызывает остановку AWG. `ExecStopPost` watchdog очищает интерфейс, включая аварийное завершение supervisord-процесса.

Временное окно между двухсекундными проверками не гарантирует миллисекундное мгновенное отключение. Это ограничение должно присутствовать в SLA.

### Разделение ответственности

- **Интернет-подключение AWG**: требует отдельного проверенного IPv4 forwarding/NAT + наружного E2E с устройством. Пока этого нет, выдавать AWG как рабочий нельзя. Подписку VLESS нельзя подменять конфигурацией AWG: нужен формат AWG 3.1 в поддерживаемом клиенте.
- **Персональный Smart DNS**: существующий бэкенд MNEBYVPN под `*.dns.mnebyvpn.site` уже ведёт учёт по PostgreSQL, PIN-правилу DNS и SNI-метке. Сертификат `fi.mnebyvpn.site` **не подходит** для 12-символьных персональных DoT-имен; нельзя превращать стандартный CoreDNS в публичный резолвер. Новая страна сначала должна включаться как премиальный egress/backend через защищённый узел или получить отдельный wildcard/индивидуальный выпуск с тем же контроллером.
- **Центральная публикация**: `nodekit-controller-catalog.ts` и signed VLESS receipts уже есть в MNEBYVPN. Только после внешних E2E/egress-country, синхронизации expiry/revoke, operator promotion и разрешения release flag добавлять узел в действующую подписку.

### Проверка на новом узле

Actions `nodekit-prepare-new-vps.yml`: `awg_watchdog_install` и `awg_grants_inspect`. При запуске `fleet bootstrap` watchdog устанавливается без активации. Контроль безопасности: выполнять повторные bootstrap без изменения ключей, проверять целостность, одиночность адресов и режим без клиентов до выдачи первой подписки.

Официальные первоисточники: [AmneziaWG Go](https://github.com/amnezia-vpn/amneziawg-go) и [AmneziaWG tools](https://github.com/amnezia-vpn/amneziawg-tools); команда `awg syncconf` используется в [официальном systemd service](https://github.com/amnezia-vpn/amneziawg-tools/blob/master/src/systemd/wg-quick@.service).

Security review (2026-11-18): the node accepts no caller-supplied controller public key; only its pinned SPKI, and every signed grant expires within **60 minutes** even if the central controller is unavailable. A future delivery worker must refresh active leases before expiry (e.g. every 15 min). Live AWG peer `AllowedIPs` are checked exactly, not just the peer keys.
