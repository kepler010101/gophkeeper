# GophKeeper

Клиент‑серверный менеджер приватных данных на Go.

## Что реализовано

- Регистрация и логин (JWT, bcrypt)
- CRUD: create/list/get/delete
- Шифрование payload на сервере (AES‑256‑GCM, master key + DEK)
- Метаданные в открытом виде (jsonb)
- Хранение в PostgreSQL
- TLS (HTTPS), dev‑сертификаты
- CLI клиент для Windows/Linux/macOS с `--version`
- Read‑only режим клиента при потере соединения
- Unit‑tests и coverage >= 80% при запуске с тестовой БД
- Поиск по метаданным (`list --search` / `GET /api/v1/items?q=...`)
- Команда `sync` для загрузки всех данных в кэш
- Тип данных `otp` и команда `otp`

## Как поднять

Postgres:
```
docker-compose up -d postgres
```

Сертификаты:
```
make gen-cert
```

Переменные окружения:
```bash
export DATABASE_URL=postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable
export GOPHKEEPER_JWT_SECRET=dev_jwt_secret_32_chars_min_123456
export GOPHKEEPER_MASTER_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
```

Запуск сервера:
```
make run-server
```

## CLI примеры

Регистрация/логин:
```bash
gophkeeper register --username user1 --password pass1 --server https://localhost:8443 --insecure
gophkeeper login --username user1 --password pass1 --server https://localhost:8443 --insecure
```

Загрузка данных:
```bash
gophkeeper put --type text --meta title=note --data "hello" --insecure
gophkeeper put --type binary --meta name=file --file ./file.bin --insecure
gophkeeper put --type otp --meta name=github --data "JBSWY3DPEHPK3PXP" --insecure
```

Список и поиск:
```bash
gophkeeper list --insecure
gophkeeper list --search github --insecure
```

Получение данных:
```bash
gophkeeper get --id <id> --out ./output.bin --insecure
gophkeeper otp --id <id> --insecure
```

Удаление:
```bash
gophkeeper delete --id <id> --insecure
```

Синхронизация в кэш:
```bash
gophkeeper sync --insecure
```

`--insecure` нужен только для self‑signed в dev.

## Read‑only режим

При ошибке сети/TLS клиент переходит в read‑only:
- `register/login/put/delete/sync` запрещены
- `list/get/otp` работают только из локального кэша

Кэш: `~/.gophkeeper/cache/` (можно переопределить `GOPHKEEPER_HOME`).

## Переменные окружения

Сервер:
- `DATABASE_URL` или `GOPHKEEPER_DB_DSN` — строка подключения Postgres
- `GOPHKEEPER_JWT_SECRET` — секрет JWT (>= 32 символов)
- `GOPHKEEPER_MASTER_KEY` — base64 ключ 32 байта
- `GOPHKEEPER_ADDR` — адрес сервера (по умолчанию `:8443`)
- `GOPHKEEPER_TLS_CERT` — путь к cert (по умолчанию `./certs/server.crt`)
- `GOPHKEEPER_TLS_KEY` — путь к key (по умолчанию `./certs/server.key`)

Клиент:
- `GOPHKEEPER_HOME` — база для локального состояния

Тесты:
- `GOPHKEEPER_TEST_DB` — DSN тестовой БД для интеграционных тестов хранилища

## Архитектура шифрования

Для каждого item генерируется DEK (32 байта).
Payload шифруется DEK (AES‑GCM), DEK шифруется master key (AES‑GCM).
В БД лежат ciphertext и nonce‑поля, метаданные не шифруются.

## Сборка и тесты

```
make build
make test
```

Проверка покрытия:
```
GOPHKEEPER_TEST_DB=postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable \
go test ./... -coverprofile=coverage.out -coverpkg=./...
```

## Кросс‑компиляция

```bash
GOOS=linux GOARCH=amd64 go build -o bin/server-linux ./cmd/server
GOOS=windows GOARCH=amd64 go build -o bin/client.exe ./cmd/client
GOOS=darwin GOARCH=arm64 go build -o bin/client-mac ./cmd/client
```
