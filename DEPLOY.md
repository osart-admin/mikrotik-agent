# Развёртывание

Инструкция для Linux-хоста, на котором уже что-то крутится — например, обратный прокси на
80/443 и другое приложение на 8080. Ниже это учтено: сервис слушает только `127.0.0.1:8090`
и отдаётся через существующий прокси.

Подставьте свои значения вместо `<docker-host>` и `mikrotik.example.com`.

## 1. Доступ по SSH

Чтобы разворачивать и обслуживать сервис без пароля, добавьте публичный ключ своей рабочей
машины на хост — **выполнить на `<docker-host>`**:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo '<содержимое вашего ~/.ssh/id_ed25519.pub>' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

## 2. Что должно быть установлено

```bash
docker --version && docker compose version && git --version
```

Если Docker нет — официальный репозиторий, не `apt install docker.io`:

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin git
sudo usermod -aG docker $USER   # перелогиниться после этого
```

## 3. Проверить главное: видит ли хост все роутеры

Это точка сбора — если с неё не видно площадку, сервис бесполезен. **До** развёртывания:

```bash
for ip in <IP роутера 1> <IP роутера 2> ...; do
  timeout 3 bash -c "</dev/tcp/$ip/22" 2>/dev/null && echo "$ip:22 OK" || echo "$ip:22 НЕТ"
done
```

Всё, что отвечает «НЕТ», надо решить маршрутизацией/туннелем до запуска, иначе эти устройства
будут вечно висеть в статусе `unreachable`.

## 4. Развернуть

```bash
git clone <repo> ~/mikrotik-agent && cd ~/mikrotik-agent
docker compose up -d --build
docker compose logs -f
```

`data/` с машины разработки **не копируйте** — ключи и пароли заведутся заново через UI. Если всё же
переносите, то целиком вместе с `data/master.key`, иначе `.enc`-значения не расшифруются.

Порт публикуется как `127.0.0.1:8090` — снаружи хоста недоступен. Это осознанно: сервис держит
SSH-ключи ко всему парку.

Часовой пояс задаётся `APP_TIMEZONE` в `docker-compose.yml`.

## 5. Отдать через существующий Caddy

Если на хосте уже стоит Caddy, он терминирует TLS и получает сертификаты сам. Добавить в
`/etc/caddy/Caddyfile`:

```
mikrotik.example.com {
    reverse_proxy 127.0.0.1:8090
}
```

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Имя обязательно: Caddy с автоматическим HTTPS отвечает только по SNI, на голый IP сертификата нет. Для внутреннего имени без публичного DNS используйте
`tls internal` (Caddy выпустит свой CA) либо существующий wildcard-сертификат.

Ограничить доступ только своей сетью или VPN:

```
mikrotik.example.com {
    @allowed remote_ip 10.0.0.0/8
    handle @allowed {
        reverse_proxy 127.0.0.1:8090
    }
    respond 403
}
```

## 6. После первого запуска

1. Открыть сайт → создать администратора (первая форма).
2. Настройки → вставить ключ OpenAI → «Проверить ключ».
3. Импорт из Winbox или добавить устройства руками.
4. На каждом — «Выполнить онбординг» (создаст на роутере группу `mikrotik-agent-ro` с политиками
   `ssh,read` и зальёт ключ агента; админ-пароль не сохраняется).
5. «Собрать всё», затем Настройки → интервал автосбора.

## 7. Бэкап

Единственное, что нельзя потерять — `data/master.key`: без него не расшифровать ни API-ключ, ни
пароли устройств. История конфигов лежит в git-репозитории `data/configs`.

```bash
tar czf mikrotik-agent-data-$(date +%F).tar.gz -C ~/mikrotik-agent data
```
