# MNEBYVPN: единый маршрут выпуска на сервер 188

**Источник доступа:** репозиторий [grunvald91/telegram-proxy-infra](https://github.com/grunvald91/telegram-proxy-infra). Сервер 188.120.254.223 доступен существующим GitHub Actions SSH-подключением через секрет SERVER188_SSH_PASSWORD этого инфраструктурного репозитория. Доступ уже использовался в успешных релизах.

**Не просить повторно** MNEBYVPN_DEPLOY_HOST, MNEBYVPN_DEPLOY_USER, MNEBYVPN_DEPLOY_SSH_KEY, MNEBYVPN_DEPLOY_KNOWN_HOSTS в репозитории Mnebyvpn. Эти переменные относятся к устаревшему второму пути, а не к развернутой инфраструктуре.

## Реальный продакшен

- Сайт: автоматический workflow .github/workflows/mnebyvpn-main-auto-public.yml.
- Telegram-бот: автоматический workflow .github/workflows/mnebyvpn-main-auto-bot.yml.
- Оба сценария запускаются по расписанию каждые 15 минут и вручную из GitHub Actions.
- Оба проверяют успешный CI исходного Mnebyvpn main, используют существующий secret, работающее staging-окружение, canary, ограниченный перезапуск принадлежащих MNEBYVPN контейнеров и rollback.
- Общая группа очереди mnebyvpn-auto-public-deploy не допускает одновременно перезапускать staging, который используют сайт и бот.
- Настоящее размещение: /opt/mnebyvpn/releases/SHA, контейнер mnebyvpn-bot-info, порт 127.0.0.1:8793, mnebyvpn-public-web на 127.0.0.1:8792. Данные и secrets в /opt/mnebyvpn, а не в Git.
- Платёжный секрет Prodamus хранится как Actions secret PRODAMUS_SIGN_SECRET **в этом** репозитории. Для переноса на 188 существует отдельный ручной workflow mnebyvpn-prodamus-secret-stage.yml. Никогда не выводить ключ в логи или код.

## Правила, чтобы не возвращаться к старой проблеме

1. Для любой проверки MNEBYVPN сначала смотреть этот репозиторий, его Actions и существующие скрипты scripts/mnebyvpn-*.sh, затем состояние конкретного MNEBYVPN-контейнера. Не начинать работу с предположения об отсутствующих SSH-секретах исходного репозитория.
2. Новый релиз исходного Mnebyvpn main автоматически подхватывается в инфраструктурных workflows. Для немедленной попытки использовать Run workflow mnebyvpn-main-auto-bot.yml или mnebyvpn-main-auto-public.yml.
3. Перед заменой контейнера требовать зелёный исходный CI, актуальный SHA, рабочий staging; проверять /readyz и 401 для неподписанного Telegram webhook. При ошибке сохранять предыдущую версию.
4. Нельзя затрагивать Telegram proxy, nginx, Xray, музыкальную синхронизацию, другие контейнеры и публичные firewall без отдельных замеров и плана изменений.
5. Выкладка кода не подтверждает действительность коммерческих платежей. Stars и Prodamus, опубликованные тарифы, возвраты и выдача VPN требуют E2E.

## 2026-11-10 · Ручное управление Smart DNS

После успешного CI [Mnebyvpn main 15de829e1e05d1ee3d7ae1fca8283e8e24b04951](https://github.com/grunvald91/Mnebyvpn/commit/15de829e1e05d1ee3d7ae1fca8283e8e24b04951) запрошена публикация Telegram-бота с owner-only меню доменов (PR #87), двухэтапным подтверждением маршрутов и миграцией 0109. Автоматический canary должен сохранить текущий контейнер при ошибке. Этот релиз не меняет Oracle, CoreDNS, Nginx, Xray или внешний DNS. Для автоматического применения маршрутов нужен отдельно проверенный infrastructure PR #63.

## 2026-11-10 · Покупка VPN через HTML Bubble

Источник MNEBYVPN main: [7c47f87512f04e36cf24f618f9720647a17748ce](https://github.com/grunvald91/Mnebyvpn/commit/7c47f87512f04e36cf24f618f9720647a17748ce), PR #92. CI исходника: [42824984339](https://github.com/grunvald91/Mnebyvpn/actions/runs/42824984339) — success. Разрешена изолированная публикация существующего Telegram-бота: экран тарифов VPN теперь sendWidget HTML с Telegram Stars; платежи и выдача не менялись. Этот commit документации запускает стандартный проверяемый bot auto-release на сервер 188 с canary и rollback. Наличие успешного деплоя не означает проверку живой покупки Stars.

## 2026-11-10 · Отображение ошибок ACTIVE доменов

Mnebyvpn main [0cb28e4a74718cf0c08cc4c0bb5c1929c29a7553](https://github.com/grunvald91/Mnebyvpn/commit/0cb28e4a74718cf0c08cc4c0bb5c1929c29a7553), verified CI [42839511601](https://github.com/grunvald91/Mnebyvpn/actions/runs/42839511601), owner-only DNS admin UI now marks `ACTIVE_ROUTE_CHECK_FAILED` in list/card. Request existing guarded Telegram bot auto deployment; does not change CoreDNS/Nginx or pre-existing Oracle routes.

## 2026-11-10 · Неоновый Telegram HTML Bubble покупки VPN

После [PR #94](https://github.com/grunvald91/Mnebyvpn/pull/94) исходник `Mnebyvpn/main` [c902aa492a73d6f4d7444f8e5b474f8aed707fb9](https://github.com/grunvald91/Mnebyvpn/commit/c902aa492a73d6f4d7444f8e5b474f8aed707fb9) прошёл [CI 42848328078](https://github.com/grunvald91/Mnebyvpn/actions/runs/42848328078) (success). Дизайн покупки VPN изменён на лёгкий неоновый cyan/indigo/violet с воздушными кнопками; валюта Stars, цены, серверные ключи тарифа, платёжный обработчик и выдача VPN не менялись. Запрос только на guarded canary-redeploy MNEBYVPN Telegram-бота через существующий SSH-путь (с rollback). Сетевые сервисы, DNS и nginx не затрагивать. Живую оплату Stars считать НЕ ПРОВЕРЕННОЙ до E2E.

## 2026-11-10 · Реальная аватарка в Telegram HTML Bubble

Визуальное исправление [PR #97](https://github.com/grunvald91/Mnebyvpn/pull/97) в MNEBYVPN `main`: [394d1a1c868021071e953a0bf940fcd4b3ffdfa5](https://github.com/grunvald91/Mnebyvpn/commit/394d1a1c868021071e953a0bf940fcd4b3ffdfa5). Исходный CI [42871683213](https://github.com/grunvald91/Mnebyvpn/actions/runs/42871683213) success. Зафиксирован настоящий аватар MNEBYVPN (Земля и разрушенная стена) как локальное встроенное изображение в HTML Bubble, фирменная цветовая схема, сохранены цены VPN и оплата Stars. Запрос на штатный guarded bot deploy через сервер188 с canary/rollback. Не менять DNS, сетевые процессы, nginx, TLS и другие контейнеры. Живой платёж Stars и VPN выдача требуют отдельного подтверждения E2E.
