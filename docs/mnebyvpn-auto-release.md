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
