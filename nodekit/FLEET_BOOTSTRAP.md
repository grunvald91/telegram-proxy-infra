# Nodekit: автоматизированное развёртывание новых стран (v1)

Статус: **повторяемое автоматическое развёртывание в режиме staging/canary**, не активация платных клиентов. Репозиторий [grunvald91/telegram-proxy-infra](https://github.com/grunvald91/telegram-proxy-infra).

## Контракт для любого нового VPS

Источником истины служит одобренный и слитый в `main` файл `nodekit/fleet/<cc>.json`. Пользовательская ссылка — строго `<cc>.mnebyvpn.site`, где `cc` — двухбуквенный код страны. Внутренний `node_id` от публичного имени отделён. Смена IP и замена ключей требуют отдельного ревью, не подменяются данными входящего webhook.

В инвентаре хранятся **только несекретные** данные: IPv4 VPS, публичный FQDN, ID, список компонентов, фиксированные порты, стадия `testing`/ `approved`, положительное согласование автоматической подготовки, запрет публикации и необязательный SHA-256 уже созданной публичной Ed25519 идентичности. Никаких паролей, частных VPN/DNS ключей и токенов API в Git.

`nodekit/fleet_plan.py` проверяет каждое поле, исключает уже работающие 89/188, частные/зарезервированные IP и запрещает любые специальные символы в именах SSH. Его вывод — стандартный `nodekit/nodekit.py` spec v1. Секреты получают только GitHub environment конкретной страны; исполняющий раннер никогда не принимает IP/имя VPS из произвольного `repository_dispatch` payload.

## Автоматизированные стадии

Workflow `MNEBYVPN fleet bootstrap (inventory-approved, subscribers off)`: `.github/workflows/nodekit-fleet-bootstrap.yml`.

1. **bootstrap** — после приобретения и регистрации VPS: предконтроль spec и свободных портов, локальная Ed25519 идентичность, SHA-256 pinned Xray/CoreDNS/Nginx, сборка AWG 3.1 из двух зафиксированных upstream commits, SHA-256 всех бинарников, уникальные локальные REALITY/AWG ключи, пустые настройки VPN без клиентов, безопасный Nginx SNI/CoreDNS кандидат; systemd для AWG устанавливается, **но остаётся выключен**. Запуск повторно идемпотентен при совпадении бинарников, идентичности и политик.
2. **certificate** — после корректной A-записи: Let's Encrypt HTTP-01, проверка CA/hostname/private key, автоматическое продление и копирование сертификата в закрытый каталог.
3. **canary** — AWG 3.1 *временно запускается без клиентов и останавливается*; на loopback выполняются TLS handshake и DNS A запрос к CoreDNS. Нет публичного DNS 853 и нет авторизованных VPN-пиров.
4. **inspect** — сверка AWG manifest, статуса systemd и действительности сертификата.

Механизм `repository_dispatch` (`event_type=nodekit-bootstrap-approved`, `client_payload.country=cc`) позволяет доверенному controller запустить **только bootstrap** после приобретения VPS и внесения одобренной инвентарной записи. Контроллер не может передать другой IP или произвольный скрипт через dispatch. Задействован `workflow_dispatch` для ручного перезапуска после ошибок.

Работа GitHub Actions **не создаёт** VPS у провайдера и не расходует бюджет хостинга; для этого потребуется отдельная подтверждённая интеграция провайдера с жёстким бюджетом, как описано в `grunvald91/Mnebyvpn/docs/scale-out-contract.md`.

## SSH и граница доверия

Для новой страны необходимо создать GitHub Actions environment `node-<cc>` (например, `node-nl`) с секретами:
- `NODEKIT_SSH_USER=root`;
- `NODEKIT_SSH_PASSWORD` — **уникальный пароль только этого нового VPS**;
- `NODEKIT_SSH_KNOWN_HOSTS` — предварительно независимо проверенная SSH host public key запись для его IP (не ключ доступа клиента). В целях безопасности ожидается `StrictHostKeyChecking=yes`. Для нового производственного VPS **не использовать** TOFU.

Для существующего изолированного `fi` временно поддерживается старое хранилище `MNEBYVPN_NEW_NODE_SSH_USER`/`MNEBYVPN_NEW_NODE_SSH_PASSWORD` и TOFU `accept-new`. Это исключение не переносится на новые страны. Доступ к environment желательно дополнительно защитить ручным approval.

## Что пока НЕ автоматизировано

- Покупка VPS и подтверждение расхода, выдача DNS A у Jino и провайдерские ACL.
- Клиентские AWG peers, серверное NAT, постоянный сервис для клиентского трафика, hard-expiry/revoke и реальный E2E на Android.
- Персональный DNS доступ на новой стране: продукт имеет существующий механизм `apps/service/src/personal-dot-production.ts` в `grunvald91/Mnebyvpn`. Включать общий SNI/DoT `fi.mnebyvpn.site` как публичный резолвер недопустимо: сначала требуется проверка индивидуальной личной ссылки и её отключение через entitlement. Для настоящих персональных Android Private DNS адресов нужен подходящий wildcard TLS сертификат и авторизация на обслуживающем узле.
- Регистрация node в живом controller, независимые E2E/exit-country, согласованный отзыв клиента на всех узлах, подтверждение страны и добавление в подписку.

**Ни одна стадия этого workflow не включает подписки**. Следующий production rollout должен использовать отдельный подписанный контроллером service-release с E2E gate и автоматическим откатом. Страна в подписке определяется внешней проверкой egress, а не двухбуквенным названием DNS или из инвентаря.

Первоисточники AWG: https://github.com/amnezia-vpn/amneziawg-go и https://github.com/amnezia-vpn/amneziawg-tools ; документация GitHub repository_dispatch: https://docs.github.com/en/rest/repos/repos#create-a-repository-dispatch-event .


## 188 and Telegram proxy are not optional architectural substitutions

The existing central controller is `188.120.254.223` with MNEBYVPN site,
Telegram bot, PostgreSQL and subscription workers. Do not commission a
second authority or copy signing keys into Actions. The `sni-proxy` field
in the immutable v1 FI spec denotes the staged **SmartDNS Nginx SNI
transport**, NOT a customer Telegram proxy. The customer proxy target is
**Telemt MTProto**, controlled by separate per-entitlement credentials,
expiry and revoke. It is not yet installed on FI. Do not re-stage/overwrite
the existing FI v1 manifest to fix this label; add Telemt as a separately
reviewed schema v2 component after its secure installer is complete.
See [CONTROLLER188_TELEGRAM_PROXY.md](CONTROLLER188_TELEGRAM_PROXY.md).
