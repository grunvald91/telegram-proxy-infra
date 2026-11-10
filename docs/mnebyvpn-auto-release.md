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

## 2026-11-10 · Final width-200 Telegram Bubble fix

MNEBYVPN main [277eaccfab97b1fff422e8d8fb3c35356326d8c8](https://github.com/grunvald91/Mnebyvpn/commit/277eaccfab97b1fff422e8d8fb3c35356326d8c8) ([PR #98](https://github.com/grunvald91/Mnebyvpn/pull/98)), CI [42872566634](https://github.com/grunvald91/Mnebyvpn/actions/runs/42872566634) success: narrow Telegram widget 200px no overflow, same avatar and Stars checkout. Request bot-only guarded canary deployment with rollback. No DNS, network or payment backend changes; live Stars charge remains unverified until real payment E2E.

## 2026-11-10 · Verified inherited MNEBYDNS Antigravity routes (COVERED)

MNEBYVPN main [77f3a150dc3d81505589e526d4bdd1f042389684](https://github.com/grunvald91/Mnebyvpn/commit/77f3a150dc3d81505589e526d4bdd1f042389684), PR #100, includes migration 0110 and owner-only bot UI for independently verified inherited CoreDNS/Nginx domain coverage, without allowing the user to remove shared routes. Source CI 42880094469 passed. Request guarded normal bot deployment and migration with backup via existing auto-bot workflow. Live route proof: [42879814092](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42879814092), 12/12 DoT and TLS verified. No DNS/Nginx restart or additional host-route changes in this release.

## 2026-11-10 · Рабочая кнопка «VPN и тарифы» → HTML Bubble

MNEBYVPN main [2262f3dafb66c2f1b73bdd1fb88f55932e6a7d2d](https://github.com/grunvald91/Mnebyvpn/commit/2262f3dafb66c2f1b73bdd1fb88f55932e6a7d2d), [PR #99](https://github.com/grunvald91/Mnebyvpn/pull/99), [main CI 42881546611](https://github.com/grunvald91/Mnebyvpn/actions/runs/42881546611) success. Telegram webhook activation [42881546676](https://github.com/grunvald91/Mnebyvpn/actions/runs/42881546676) success, `allowed_updates` includes `widget_query`. Main cabinet `nav:vpn` now returns `sendWidget` using actual published, individually validated VPN prices, preserving Stars inline fallback; old `nav:vpn:list` text remains available. No DNS, nginx, Xray, foreign ingress, firewall, or unrelated services touched. Request an isolated guarded Telegram bot auto-release via existing 188 SSH, canary and rollback. Verify bot readiness + unsigned webhook=401. Live in-chat Stars charge still requires a user test.

## 2026-11-10 · Only one purchase CTA in HTML Bubble

MNEBYVPN main [c86aa2e6953b56afc8bf28bbf6d2c0396e3f9553](https://github.com/grunvald91/Mnebyvpn/commit/c86aa2e6953b56afc8bf28bbf6d2c0396e3f9553), [PR #101](https://github.com/grunvald91/Mnebyvpn/pull/101), [main CI 42884955938](https://github.com/grunvald91/Mnebyvpn/actions/runs/42884955938) success. Fix: live Telegram cabinet `🌐 VPN и тарифы` opens HTML Bubble *without secondary inline tariff buttons*; one internal Stars purchase CTA sends Telegram native invoice via existing credential. Widget payment errors are shown in-card instead of prompting another button. Read-only runtime audit [42884819784](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42884819784) confirmed existing original outbound bot token configured, Telegram reachable and bot ready. Guarded canary rollout of only the existing MNEBYVPN Telegram bot, with rollback. Do not touch nginx, DNS, Xray or other containers. Native Stars payment confirmation remains mandatory; live charge/E2E has not been exercised.

## 2026-11-11 · New Telegram home menu Bubble and direct Stars invoice links

Source: MNEBYVPN main [1c66aa46de40f1e6394dee6fddb15991d99b3547](https://github.com/grunvald91/Mnebyvpn/commit/1c66aa46de40f1e6394dee6fddb15991d99b3547) via [PR #102](https://github.com/grunvald91/Mnebyvpn/pull/102), full CI [42908560508](https://github.com/grunvald91/Mnebyvpn/actions/runs/42908560508) success. Telegram primary `/start` and `nav:home` now send an actual brand-avatar HTML widget with all normal menu actions, while keeping ONE inline `nav:menu:legacy` fallback for clients without Telegram Widgets. The VPN checkout widget no longer repeats duration/Stars in its caption. It pre-generates user- and offer-bound Telegram Stars `createInvoiceLink` URLs and uses `TelegramWidget.openTelegramLink` on a single pay tap, opening native invoice confirmation without a separate chat invoice. Orders are created only on verified Telegram pre-checkout, by signed per-user link/UUID, with existing durable Stars verification and settlement. Production `TELEGRAM_TOKEN_BOT` presence and Telegram egress were confirmed read-only in [42884819784](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/42884819784). Request isolated guarded Telegram bot deployment on 188 only (canary, rollback, webhook auth). Do not touch VPN/Xray, DNS, networks, TLS, Nginx or unrelated services. No actual charge performed in deployment.
