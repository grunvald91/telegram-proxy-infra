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

Механизм `repository_dispatch` (`event_type=nodekit-bootstrap-approved`, `client_payload.country=cc`) позволяет доверенному controller запустить **полную безопасную подготовку `auto`** после приобретения VPS и внесения одобренной инвентарной записи. Контроллер не может передать другой IP или произвольный скрипт через dispatch. Задействован `workflow_dispatch` для ручного перезапуска после ошибок.

Работа GitHub Actions **не создаёт** VPS у провайдера и не расходует бюджет хостинга; для этого потребуется отдельная подтверждённая интеграция провайдера с жёстким бюджетом, как описано в `grunvald91/Mnebyvpn/docs/scale-out-contract.md`.

## SSH и граница доверия — автоматический первый контакт

После получения VPS с учётными данными из настроенного источника credentials, fleet workflow **не просит вводить SSH host key вручную**.

1. GitHub Actions проверяет `nodekit/fleet/<cc>.json` и по заранее закреплённому SSH подключается к **существующему RU188**.
2. На RU188 исполняется `nodekit/fleet_host_trust.py`. При первом обращении он запрашивает публичный Ed25519 host key у указанного в инвентаре IP (SSH keyscan без передачи пароля), записывает его в root-only `/root/mnebyvpn-controller/fleet-ssh-host-keys/<cc>-<node_id>.known_hosts` атомарно с `O_EXCL`, защищает запись межпроцессной блокировкой и выводит публичный pinned key.
3. Если заранее задан публичный ключ `NODEKIT_SSH_KNOWN_HOSTS`, он проверяется **до** первого сохранения в RU188. При несовпадении первый контакт прекращается, ошибочный pin не записывается. Если такого ключа нет, используется явная TOFU-политика.
4. Все подключения к новому VPS используют `StrictHostKeyChecking=yes` с этим сохранённым ключом. При замене host key или попытке привязать тот же `node_id` к другому IP процесс **останавливается**. Новую идентичность следует развернуть с новым node_id/manifest в рамках отдельной автоматизированной замены узла, но старая запись не переписывается.
5. Для ранее созданного FI допускается наследуемая **парольная пара конкретного FI**; для других стран обязательны отдельные машинно выданные credentials. Приватные ключи контроллера и SSH-пароли не сохраняются в инвентаре и не выводятся в CI.

**Ограничение безопасности:** это Trust on First Use (TOFU). Первый ключ получен по неаутентифицированному каналу; он защищает **последующие** подключения от тихой подмены, но не доказывает владение сервером при первом контакте. Если провайдер предоставляет API удостоверения host key, автоматизированный attestation через него следует использовать до первого парольного SSH. Успешное SSH-соединение не доказывает подлинность сервера, качество VPN или доступность DNS.

## Полностью автоматическая подготовительная цепочка

Обновление разрешённых `nodekit/fleet/*.json` в `main` автоматически выбирает изменённые страны (до 8 за push) и запускает цепочку для каждой; явный запуск контроллером через `repository_dispatch` и диагностика через `workflow_dispatch` также поддерживаются. `repository_dispatch` и `workflow_dispatch` теперь используют `phase=auto` как штатный режим. Это **один запуск**: inventory → сохранение первого SSH ключа на RU188 → bootstrap Nodekit/AWG/DNS-stage → ACME certificate → пустой AWG/DNS canary → read-only inspect. Ошибка останавливает процесс и не включает клиентские ссылки. Отдельные фазы доступны для диагностики, но не нужны при нормальном развёртывании.

Текущая AWG сборка выполняется для `x86_64`: до передачи бинарников workflow проверяет архитектуру целевого VPS и отказывается продолжать установку на другой архитектуре, не отправляя несовместимый бинарник. Для ARM64 нужен отдельный проверенный toolchain и тесты.

Push, в котором ни одна актуальная запись инвентаря не добавлена и не изменена, не запускает пустую матрицу серверов.

Это **автоматизация подготовки**, а не полноценная выдача платных подписок. Для end-to-end Zero Touch дополнительно нужны заранее настроенные интеграции API провайдера VPS, DNS и выдачи отдельных credentials (без ручного добавления secrets по стране), доверенная регистрация node на RU188, hard-expiry/revoke, Telemt MTProto installer, независимые E2E и подтверждение страны выхода. Пока этих частей нет, `SUBSCRIBER_PUBLICATION=false`, а `FI` не следует объявлять рабочим клиентским узлом.
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
