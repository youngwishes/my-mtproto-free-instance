# Telemt SYN limit for Docker

`telemt-syn-limit` ограничивает частоту новых TCP-подключений к опубликованному
Docker-порту Telemt `443`. Существующие TCP-соединения limiter не затрагивает.

Основной `playbook.yml` разворачивает приложение и затем включает limiter на
хостах `mtproto_servers` последовательно (`serial: 1`). Отдельный
`telemt-syn-limit.yml` обновляет только limiter.

Рабочий профиль:

- порт `443/tcp`;
- лимит `54/minute` для каждого source IPv4;
- burst `5`;
- превышение отклоняется через `tcp-reset`.

Трафик опубликованного Docker-порта проходит через `DOCKER-USER`. Сервис
создаёт цепочку `TELEMT_SYN_LIMIT` и подключает её первым правилом для входящих
TCP SYN на порт `443`. Systemd unit идемпотентно пересоздаёт правила при старте
и удаляет все переходы в собственную цепочку и саму цепочку при остановке.
Ansible проверяет фактические правила и перезапускает unit, если firewall был
очищен независимо от systemd.

## Проверка

```bash
systemctl is-enabled telemt-syn-limit
systemctl is-active telemt-syn-limit
iptables -vnL DOCKER-USER --line-numbers
iptables -vnL TELEMT_SYN_LIMIT --line-numbers
```

Ожидается один переход из `DOCKER-USER` в `TELEMT_SYN_LIMIT`. Первое правило
цепочки пропускает SYN в пределах `54/minute` с burst `5`, второе отвечает
`tcp-reset` на превышение.

## Управление и rollback

Обновить только limiter:

```bash
ansible-playbook telemt-syn-limit.yml
```

Остановить и отключить limiter на всех хостах последовательно:

```bash
ansible-playbook telemt-syn-limit-rollback.yml
```

Для canary-проверки можно добавить `--limit free1`. Rollback не перезапускает
и не изменяет контейнер Telemt.

## Ограничение CGNAT

Лимит применяется по source IPv4. Клиенты одного мобильного оператора за
carrier-grade NAT могут совместно использовать `54/minute`, поэтому менять
rate или burst следует после проверки счётчиков RETURN/REJECT и жалоб клиентов.
