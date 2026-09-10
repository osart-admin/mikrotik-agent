# Развёртывание на 10.10.0.54

Хост уже занят другими сервисами — учтено ниже.
Обнаружено сканированием 2026-09-10: Ubuntu 22.04 (OpenSSH 8.9), **Caddy** на 80/443,
**GLPI** на Apache:8080. Порт 8090 свободен, Docker API наружу не открыт.

## 1. Доступ по SSH

С этого Mac вход не проходит (`Permission denied (publickey,password)` для `admin` и `root`),
хотя записи в `known_hosts` есть. Нужно добавить публичный ключ Mac нужному пользователю —
**выполнить на 10.10.0.54**, войдя как вы обычно входите:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF+DxWfvHYtNGaVKzOaH3hCsxQaJDvqvw4Ttl9ItAtC2 admin@arm.ms' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

(это `~/.ssh/id_ed25519.pub` с Mac — тот же ключ, что уже прописан на домашнем hAP)

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
for ip in 10.0.3.254 10.10.4.1 <остальные IP роутеров>; do
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

`data/` с Mac **не копируйте** — ключи и пароли заведутся заново через UI. Если всё же
переносите, то целиком вместе с `data/master.key`, иначе `.enc`-значения не расшифруются.

Порт публикуется как `127.0.0.1:8090` — снаружи хоста недоступен. Это осознанно: сервис держит
SSH-ключи ко всему парку.

Часовой пояс в `docker-compose.yml` сейчас `Europe/Berlin` — поправьте, если хост живёт в другом.

## 5. Отдать через существующий Caddy

Caddy на хосте уже терминирует TLS и умеет получать сертификаты сам. Добавить в
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

Подставьте реальное имя — Caddy на этом хосте отвечает только по SNI, на голый IP сертификата
нет, так что имя обязательно. Для внутреннего имени без публичного DNS используйте
`tls internal` (Caddy выпустит свой CA) либо существующий wildcard-сертификат.

Ограничить доступ только офисной сетью/VPN:

```
mikrotik.example.com {
    @allowed remote_ip 10.10.0.0/16 10.0.3.0/24
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
