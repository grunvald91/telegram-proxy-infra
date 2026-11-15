# ТЗ: Серверная десинхронизация Geneva (дубликат ACK с неверной контрольной суммой) — повтор ячейки D

**Дата:** 2026-11-15  
**База:** `Telegram-proxy-infra` (`pr-87-experiment`, RU `188.120.254.223` + DE `89.125.90.101`)  
**Статус:** Утверждённое техническое задание после ревью.

---

## 1. Цель и гипотеза

Предыдущий механизм (`window clamp` 4/8/16 байт) направлен на клиентскую сегментацию `ClientHello`. Данное отдельное ТЗ проверяет **серверную TCP-десинхронизацию по схеме Geneva (дубликат ACK с неверной TCP-контрольной суммой)** на несегментированном `ClientHello` для `i.instagram.com` (повтор **ячейки D**).

**Гипотеза:** если сразу вслед за серверным `SYN+ACK` отправить клиенту дубликат пакета с флагом `ACK` и заведомо неверной TCP-контрольной суммой (`badsum`), стек ОС клиента отбросит битый пакет, а ТСПУ десинхронизирует состояние потока и пропустит последующий обычный `ClientHello` для `i.instagram.com`.

## 2. Матрица прогона и критерии оценки

Используется раннер [mneby_tz_experiment_runner.py](../scripts/mneby_tz_experiment_runner.py):
- **Ячейка B (контроль с включённым Geneva):** контрольный SNI (`gemini.google.com`), 20 попыток. Должна давать `>= 19/20` (95%+) успеха — доказывает, что дубликат `ACK` с `badsum` не ломает обычный TLS.
- **Ячейка D (цель с включённым Geneva):** `i.instagram.com`, 20 попыток (`window clamp` выключен).
- *(Опционально перед B/D — короткий контроль `C` без вмешательства или сравнение с ранее снятой ячейкой `C`.)*

**Критерии валидности и вердикта:**
1. В `phone-sni.json` на RU `ens3` зафиксированы исходящие `SYN+ACK` и минимум 1 исходящий `ACK` с подтверждённо битой TCP-контрольной суммой (`egress_dupack_badsum > 0`) при `kernel_drops == 0`.
2. Если `egress_dupack_badsum == 0` при наличии входящих `SYN` — эксперимент **невалиден** (offload/гипервизор пересчитал или отбросил битую сумму).
3. Если ячейка B `>= 19/20` и ячейка D `>= 18/20` (90%+) — **РАБОТАЕТ**.
4. Если `egress_dupack_badsum > 0`, но `target_clienthello == 0` (или ячейка D `<= 2/20`) — **НЕ РАБОТАЕТ: ТСПУ не сбивается данным профилем Geneva**.

## 3. Техническая архитектура (по итогам ревью)

### 3.1. Без внешних зависимостей на сервере
На RU (`Ubuntu 24.04.4`, ядро `6.8.0-142-generic`) не предполагается наличие `python3-netfilterqueue` или `scapy`. Весь серверный обработчик пишется на **чистом Python stdlib**:
- приём пакетов из `NFQUEUE 211` через `AF_NETLINK` (`NETLINK_NETFILTER`);
- сборка и отправка дубликата `ACK` через `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` с `IP_HDRINCL=1` и `SO_MARK = 0x40000000` (`BYPASS`).

### 3.2. Изоляция в `nftables` и отсутствие петли / порчи `conntrack`
Продовый `telegram-nfqws.service` (`/opt/zapret2/nfqws2`, `queue 210` в `inet telegram_nfqws post` на `priority 101`) не останавливается и не редактируется.

В изолированной таблице `inet mneby_meta_v26_ru` (действует только для `--peer <IP>` или явного `all` с проверкой `ct status dnat` от `:443`):
1. `pre` (`nat prerouting priority -101`): DNAT `tcp dport 443 -> 188.120.254.223:18443`.
2. `predefrag` (`filter output priority -401`): `meta mark & 0x40000000 != 0 notrack` — гарантирует, что raw-пакеты от `IPPROTO_RAW` (с `SO_MARK = BYPASS`) обходят `conntrack` и не портят состояние соединения в ядре RU.
3. `post` (`filter postrouting priority 100` — до `telegram_nfqws` на `101`; в `NFQA_PAYLOAD` исходный порт ещё `18443`, поэтому при отправке raw-пакета порт отправителя явно подменяется на `public_sport = 443`):
   - Правило 1: для `SYN+ACK` от тестового порта `18443` с `meta mark & 0x40000000 == 0` → `counter queue num 211 bypass`.
   - Правило 2: для всех ответов тестового порта `18443` → `counter meta mark set meta mark | 0x40000000` (исключает дальнейшее попадание в продовую `queue 210`).

### 3.3. Поведение обработчика `NFQUEUE 211` и слушателя `18443`
1. Слушатель на `18443` (`WindowProxy(..., clamp_window=False)`) работает **без `TCP_WINDOW_CLAMP`** (обычное окно TCP, проксирует Meta-хосты через `tg-relay` `10.66.77.1:443` на DE, остальное на RU `188.120.254.223:443`).
2. При получении `SYN+ACK` (`seq = S0`, `ack = C0 + 1`) в `NFQUEUE 211`:
   - немедленно выносится вердикт `NF_ACCEPT` для реального `SYN+ACK`;
   - сразу после этого через `IPPROTO_RAW` (`SO_MARK = 0x40000000`) отправляется `--geneva-repeats` (по умолчанию `2`) копий пакета-дубликата `ACK` с валидным IPv4-заголовком/суммой и **испорченной TCP-контрольной суммой** (`valid_tcp_checksum ^ 0xFFFF`):
     - `ack-exact` (по умолчанию): `flags=ACK`, `seq = (S0 + 1) & 0xffffffff`, `ack = (C0 + 1) & 0xffffffff`, пустой payload;
     - `ack-desync` (параметризуемый альтернативный профиль): `flags=ACK`, `seq = (S0 + 1 + 1000) & 0xffffffff`, `ack = (C0 + 1 + 1460) & 0xffffffff`, пустой payload.

### 3.4. Замер доказательств на `ens3` (`phone-sni.json`)
В режиме `geneva` `CaptureEvidence` слушает `ens3` в обе стороны (`ip and tcp and host 188.120.254.223 and port 443` [+ peer]), хранит PCAP только в памяти и формирует:
- стандартную статистику входящих `ClientHello` (`syn`, `target_clienthello`, `sni_unsplit`, `sni_split`);
- метрики `geneva_metrics`: `synack_seen`, `dupack_sent`, `send_errors`, `egress_synack`, `egress_dupack_badsum`.

Валидация отчёта в режиме `geneva` (`validate_geneva_report`) допускает `sni_unsplit > 0` (так как цель Geneva — пропуск несегментированного `ClientHello`), но требует `kernel_drops == 0` и `egress_dupack_badsum > 0` при наличии трафика.

## 4. Обязательные проверки до живого запуска
1. Unit-тесты сборки IPv4/TCP-дубликата, порчи TCP checksum при валидной IPv4 checksum, парсинга `NFQUEUE`-сообщений, генерации `nftables`-правил и валидации `geneva_metrics`.
2. Изолированный `netns`-тест (`unshare -Urn` / root): реальный TLS-хендшейк через `nft` + `NFQUEUE 211` + `IPPROTO_RAW`, где захват фреймов на клиентском интерфейсе подтверждает наличие и валидного `SYN+ACK`, и дубликата `ACK` с неверной TCP-суммой, а клиентский TLS + echo-данные проходят без ошибок.
3. Единственный ручной запуск `meta-v30-manual-two-server-canary.yml` (`experiment_mode=geneva`) с таймером автоотката 2400 с на обоих серверах.
