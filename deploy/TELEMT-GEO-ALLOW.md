# Telemt Russian IPv4 allowlist

`telemt-geo-allow` — опциональный playbook, разрешающий новые подключения к
опубликованному Docker-порту Telemt `443/tcp` только из российских IPv4-сетей.
Основной `playbook.yml` удаляет и отключает этот allowlist; для его явного
включения используется отдельный `telemt-geo-allow.yml`. IPv6 не входит в
scope: прокси его не поддерживает.

## Источник и обновление

Роль скачивает `GeoLite2-Country.mmdb` из ветки `download` репозитория
`P3TERX/GeoLite.mmdb` и извлекает сети с кодом страны `RU`:

<https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb>

Список обновляется только при запуске отдельного `telemt-geo-allow.yml`.
Фонового timer или cron нет.

Перед активацией база проверяется и должна дать не менее 1000 российских IPv4
сетей. Новый набор загружается во временный `ipset`, после чего атомарно
подменяет активный `telemt_ru_ipv4`. Последний валидный CIDR-список хранится в
`/var/lib/telemt-geo-allow/ru-ipv4.cidr` и загружается после перезагрузки.
Для одинакового поведения на поддерживаемых версиях Ubuntu роль использует
изолированный Python venv с закреплённым `maxminddb 2.6.3`.

## Fail-closed

Systemd-сервис и пустой allowlist включаются до скачивания GeoLite2. Если при
первой установке загрузка или проверка базы завершается ошибкой, новые
подключения к `443/tcp` блокируются для всех адресов, а Ansible прекращает
последовательный rollout.

Если на сервере уже есть рабочий список, ошибка следующего обновления не меняет
активный `ipset` и сохранённый кэш. Ansible всё равно завершится с ошибкой, не
переходя к следующему серверу.

## Firewall

Сервис создаёт цепочку `TELEMT_GEO_ALLOW` и подключает её к `DOCKER-USER` для
TCP SYN на `443`. Адреса из `telemt_ru_ipv4` получают `RETURN`, остальные —
`REJECT` с `tcp-reset`. После GeoIP-фильтра российские подключения проходят
через отдельный SYN-LIMIT.

## Запуск и проверка

Обновить GeoIP allowlist без перезапуска контейнера:

```bash
ansible-playbook telemt-geo-allow.yml
```

Canary на одном сервере:

```bash
ansible-playbook telemt-geo-allow.yml --limit free1
```

Проверить состояние:

```bash
systemctl is-enabled telemt-geo-allow
systemctl is-active telemt-geo-allow
ipset list telemt_ru_ipv4
iptables -vnL DOCKER-USER --line-numbers
iptables -vnL TELEMT_GEO_ALLOW --line-numbers
```

## Rollback

```bash
ansible-playbook telemt-geo-allow-rollback.yml
```

Rollback останавливает и отключает только GeoIP-фильтр. Контейнер Telemt и
SYN-LIMIT не изменяются; после rollback прокси снова доступен с любых IPv4.

## Ограничения

GeoIP не гарантирует абсолютную точность. Российский VPN позволяет подключиться
из другой страны, а некоторые российские мобильные или корпоративные адреса
могут быть классифицированы иначе. Репозиторий P3TERX является сторонним
зеркалом GeoLite2, поэтому его доступность и цепочка поставки входят в модель
риска этого деплоя.
