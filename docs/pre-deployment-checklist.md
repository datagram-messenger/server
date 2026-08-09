# Pre-deployment checklist DGPv1

Практический runbook для выпуска `datagram-server`. Все команды выполняются из корня репозитория. Любой неожиданный diff, ненулевой код возврата, падение, race report или изменение wire-векторов означает **FAIL** до выяснения причины.

## 1. Ubuntu prerequisites и исходное состояние

Все команды ниже выполняются в Bash из корня репозитория.

```bash
sudo apt update
sudo apt install -y git ca-certificates build-essential
command -v go
go version
gcc --version
go env GOVERSION GOOS GOARCH CGO_ENABLED
. /etc/os-release && printf '%s %s\n' "$NAME" "$VERSION_ID"
uname -m
```

`build-essential` предоставляет GCC, необходимый для race detector с CGO.

## 1.1 Исходное состояние и воспроизводимость

- [ ] Зафиксировать ревизию и рабочее состояние:

```text
git rev-parse HEAD
git status --short
git diff --check
git diff --stat
git diff
```

- [ ] Осознанно проверить все незакоммиченные изменения; не удалять и не перезаписывать чужую работу.
- [ ] После всех проверок повторить `git status --short` и `git diff --check`.
- [ ] Сохранить вывод `go version`, `go env GOVERSION GOOS GOARCH CGO_ENABLED`, ОС/архитектуру и команды проверки.
- [ ] Запускать проверки в чистом CI/контейнере или на чистом checkout той же ревизии. Для воспроизводимого релиза предпочтительно закрепить точный toolchain и версии внешних инструментов.

**PASS:** известная ревизия, только ожидаемый diff, `git diff --check` без вывода. **FAIL:** неизвестные/сгенерированные файлы, whitespace errors или непонятные изменения.

## 2. Версия Go

`go.mod` объявляет `go 1.25.0`.

```text
go version
go env GOVERSION GOOS GOARCH
```

Допустима Go 1.25.0 или новее; для релизной воспроизводимости используйте закреплённую версию Go 1.25.0 либо явно документированную более новую версию. При использовании автоматической загрузки toolchain:



```bash
GOTOOLCHAIN=go1.25.0
go version
```



```bash
GOTOOLCHAIN=go1.25.0 go version
```

Загрузка отсутствующего toolchain требует сети. **PASS:** версия соответствует политике релиза и записана в evidence. **FAIL:** версия ниже 1.25.0 или отличается от закреплённой без одобрения.

## 3. Форматирование и статический анализ

Проверка `gofmt` без изменения файлов:



```bash
unformatted="$(git ls-files -z '*.go' | xargs -0 -r gofmt -l)"
printf '%s' "$unformatted"
test -z "$unformatted"

```



```bash
git ls-files -z '*.go' | xargs -0 gofmt -l
```

Если список непуст, отформатировать только перечисленные файлы командой `gofmt -w <files>`, затем просмотреть diff. После этого:

```text
go vet ./...
```

Типичная последовательность локальной диагностики: `go vet`, ограниченный fuzz, обычные tests. **PASS:** `gofmt` ничего не печатает, `go vet ./...` завершается с кодом 0. **FAIL:** любой диагностический вывод, который не разобран и не одобрен.

## 4. Обычные, повторные и targeted tests

```text
go test ./...
go test ./... -count=10
```

`-count=10` отключает использование сохранённого результата тестов и помогает выявить нестабильность. Для точечной проверки критичных сценариев:

```text
go test ./pkg/dgpserver -run '^TestServerRealTCPAuthDispatchResponseAndLifecycle$' -count=10
go test ./pkg/dgpserver -run '^(TestServerConnectRejectAndPanicNeverDispatchOrDisconnect|TestShutdownDeadlineEscalatesNetworkCancellation|TestServeInitializationFailureCompletesShutdown)$' -count=10
go test ./pkg/dgpv1 -run '^(TestSessionConcurrentRekeySafe|TestSendAndWaitCloseRaceCompletesWithoutLeak|TestConnectionShutdownCancelsBusyHandler)$' -count=10
go test ./pkg/dgpv1 -run '^(TestJSONWireVectors|TestHandshakeDeterministicVector|TestMessageGoldenVectors)$' -count=1
```

Integration/real TCP уже входит в `go test ./...`; первый targeted test явно выполняет Noise handshake, обмен сообщениями и lifecycle через loopback TCP.

**PASS:** все запуски зелёные без retry «до успеха». **FAIL:** panic, timeout, flaky result, утечка/зависание или различие wire vectors.

## 5. Coverage

```text
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

Опциональный локальный HTML-отчёт:

```text
go tool cover -html=coverage.out -o coverage.html
```

Coverage — индикатор, а не замена проверок безопасности протокола. Просмотреть function coverage прежде всего для `pkg/dgpv1`, `pkg/dgpserver` и `internal/config`; необъяснимое падение относительно предыдущего релиза — **FAIL**. Не коммитить `coverage.out`/`coverage.html`, если они не являются принятыми release artifacts.

## 6. Race detector

Race detector **явно требует `CGO_ENABLED=1` и GCC** из Ubuntu-пакета `build-essential`. Проверить:

```text
go env CGO_ENABLED
```



```bash
gcc --version

CGO_ENABLED=1 go test -race ./...
CGO_ENABLED=1 go test -race ./... -count=10




```



```bash
CGO_ENABLED=1 go test -race ./...
CGO_ENABLED=1 go test -race ./... -count=10
```

**PASS:** обе команды завершаются успешно, race report отсутствует. **FAIL:** `CGO_ENABLED=0`, нет C compiler, любой race report или падение. Невозможность запустить race detector нельзя считать успешной проверкой; её нужно выполнить в подходящем CI runner до production release.

## 7. Ограниченный fuzz

В репозитории реально существуют только следующие fuzz targets:

- `FuzzHeaderUnmarshalBinary`
- `FuzzFrameUnmarshalBinary`
- `FuzzDecodeTLVs`
- `FuzzMessageUnmarshalBinary`
- `FuzzTCPTransportReadFrame`

Без бесконечного запуска, например по 30 секунд на target:

```text
go test ./pkg/dgpv1 -run '^$' -fuzz '^FuzzHeaderUnmarshalBinary$' -fuzztime=30s
go test ./pkg/dgpv1 -run '^$' -fuzz '^FuzzFrameUnmarshalBinary$' -fuzztime=30s
go test ./pkg/dgpv1 -run '^$' -fuzz '^FuzzDecodeTLVs$' -fuzztime=30s
go test ./pkg/dgpv1 -run '^$' -fuzz '^FuzzMessageUnmarshalBinary$' -fuzztime=30s
go test ./pkg/dgpv1 -run '^$' -fuzz '^FuzzTCPTransportReadFrame$' -fuzztime=30s
```

Go переиспользует fuzz cache из build cache; поэтому результаты разных машин могут различаться. Сохранить seed/corpus или минимизированный crash input, который Go запишет в `testdata/fuzz/<Target>/`, и воспроизвести его обычным `go test`. Не очищать corpus до расследования.

**PASS:** каждый ограниченный запуск завершён без crash. **FAIL:** panic, hang, найденный failing input или невоспроизводимый сбой.

## 8. Benchmarks

На момент составления checklist функции `Benchmark...` в `*_test.go` отсутствуют, поэтому команды с выдуманными benchmark-именами запрещены. Если benchmarks появятся, сначала подтвердить их имена:



```bash
git grep -n -E '^func Benchmark[A-Za-z0-9_]+' -- '*_test.go' || true

```

Затем запускать существующие цели через `go test <package> -run '^$' -bench '<точное имя>' -benchmem`, сохраняя baseline и параметры машины. Отсутствие benchmarks сейчас не блокирует релиз; необъяснимая регрессия после их появления — **FAIL**.

## 9. Dependency integrity

```text
go mod verify
go mod tidy
git diff -- go.mod go.sum
```

`go mod tidy` может использовать сеть и **не должен молча менять зависимости**. Если diff появился, выяснить причину; без намеренного dependency change вернуть `go.mod`/`go.sum` в исходное состояние, а не включать случайное обновление.

**PASS:** `go mod verify` успешен, после `go mod tidy` нет неожиданного diff. **FAIL:** checksum mismatch, неожиданное добавление/удаление модулей или нерасследованное обновление.

## 10. Vulnerability scan — внешний инструмент

`govulncheck` не входит в стандартный Go toolchain. Установка требует сети и пишет binary в `GOBIN`/`GOPATH/bin`, но не должна менять `go.mod`:

```text
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

Для воспроизводимого CI вместо `@latest` закрепить одобренную версию инструмента. Статус: **optional** для каждого локального запуска, **required** для production release/CI gate. **FAIL:** известная достижимая уязвимость без документированного risk acceptance; ошибка установки или сети означает «не выполнено», а не PASS.

## 11. Сборка binaries

Проверка сборки всех четырёх entrypoints:



```bash
mkdir -p ./bin
go build -trimpath -o ./bin/api_datagram ./cmd/api_datagram
go build -trimpath -o ./bin/api_bot ./cmd/api_bot
go build -trimpath -o ./bin/auth ./cmd/auth
go build -trimpath -o ./bin/user ./cmd/user
sha256sum ./bin/api_datagram ./bin/api_bot ./bin/auth ./bin/user
```



```bash
mkdir -p ./bin
go build -trimpath -o ./bin/api_datagram ./cmd/api_datagram
go build -trimpath -o ./bin/api_bot ./cmd/api_bot
go build -trimpath -o ./bin/auth ./cmd/auth
go build -trimpath -o ./bin/user ./cmd/user
sha256sum ./bin/api_datagram ./bin/api_bot ./bin/auth ./bin/user
```

**PASS:** все binaries собраны для целевой `GOOS/GOARCH`; checksum и размер записаны. **FAIL:** build error или сборка не для целевой платформы. Не коммитить `bin/`.

## 12. Smoke test, конфигурация и secrets

Использовать отдельный непроизводственный `DGP_STATIC_KEY` длиной ровно 64 hex-символа; не помещать ключ в git, логи или evidence. Сохранить его вне репозитория в файле с ограниченными правами (например, `/run/secrets/dgp_static_key`). Smoke выполняется с Bash environment variables и проверкой graceful shutdown по `SIGTERM`:

```bash
export DGP_ADDRESS='127.0.0.1:8090'
export DGP_STATIC_KEY="$(tr -d '\r\n' < /run/secrets/dgp_static_key)"

log_file="$(mktemp)"
./bin/api_datagram >"$log_file" 2>&1 &
pid=$!

for _ in {1..20}; do
  kill -0 "$pid" 2>/dev/null || break
  grep -q 'DGPv1 server listening' "$log_file" && break
  sleep 0.5
done

kill -0 "$pid"
grep -q 'DGPv1 server listening' "$log_file"
ss -ltnp | grep -F '127.0.0.1:8090'

kill -TERM "$pid"
timeout 10 tail --pid="$pid" -f /dev/null
wait "$pid"

rm -f "$log_file"
unset DGP_STATIC_KEY DGP_ADDRESS
```

Для protocol-aware smoke использовать существующий real-TCP test:

```bash
go test ./pkg/dgpserver -run '^TestServerRealTCPAuthDispatchResponseAndLifecycle$' -v -count=1
```

Простое открытие TCP-порта не доказывает успешность Noise/DGPv1 handshake. **PASS:** startup, DGPv1 handshake/response/lifecycle и graceful shutdown по `SIGTERM` успешны; секреты отсутствуют в выводе. **FAIL:** plaintext response, неверный bind address, утечка ключа, зависание или некорректное завершение.

## 13. Совместимость протокола и wire vectors

- [ ] Сверить реализацию с `docs/protocol/dgp-v1.md`.
- [ ] Не менять существующие файлы `pkg/dgpv1/testdata/vectors/*.json` без отдельного protocol review.
- [ ] Выполнить:

```text
go test ./pkg/dgpv1 -run '^(TestJSONWireVectors|TestHandshakeDeterministicVector|TestMessageGoldenVectors|TestFrameMarshalBinaryWireLayout|TestHeaderMarshalBinaryWireLayout)$' -count=1
```

**PASS:** все vectors неизменны и зелёные; заявлена совместимость DGPv1. **FAIL:** wire diff, новый формат без versioning/migration plan или расхождение документации и кода.

## 14. Observability и rollback

До деплоя подтвердить:

- [ ] доступны startup/shutdown/error logs без secrets и traffic keys;
- [ ] контролируются bind/start failures, handshake/auth failures, active connections, disconnect causes, queue saturation, latency и process health доступными средствами окружения;
- [ ] есть alert thresholds и владелец реакции;
- [ ] сохранён предыдущий проверенный binary/image и его конфигурационная схема;
- [ ] rollback не меняет persistent Noise static identity неожиданно;
- [ ] описаны критерии автоматического rollback (рост ошибок handshake, crash loop, latency/connection regression);
- [ ] выполнен canary/поэтапный rollout, если это поддерживает среда.

**PASS:** rollback протестирован или достоверно воспроизводим, сигналы наблюдаемы. **FAIL:** откат требует сборки «на месте», секрет/конфигурация несовместимы или нет сигналов для решения.

## 15. Release decision и evidence

Решение **GO** возможно только когда все required gates имеют PASS, а optional gates явно отмечены как выполненные/пропущенные с причиной. Любой нерасследованный FAIL даёт **NO-GO**.

Сохранить вне репозитория или в принятом release storage:

1. commit SHA, tag/версию и финальный `git status --short`;
2. `go version`, выбранный toolchain, `GOOS/GOARCH`, `CGO_ENABLED`, сведения о C compiler;
3. логи `gofmt`, `go vet`, tests, repeated/targeted tests, race и fuzz с длительностью;
4. `coverage.out`, вывод `go tool cover -func`, при необходимости `coverage.html`;
5. вывод `go mod verify`, подтверждение отсутствия неожиданного tidy diff;
6. версию и отчёт `govulncheck` либо документированную причину пропуска локально;
7. checksums и размеры binaries/image, параметры сборки;
8. результаты smoke/integration/wire-vector checks;
9. конфигурационный manifest **без значений secrets**;
10. ссылки на dashboard/alerts, rollout и rollback plan;
11. имя одобрившего, время решения и перечень принятых рисков.

Финальная проверка:

```text
git diff --check
git status --short
```

Сгенерированные `coverage.*` и `bin/` либо удалить, либо хранить как release artifacts согласно политике, но не добавлять в commit случайно.

## 16. Release artifact verification

- [ ] Run `./scripts/build-release.sh --output ./dist --version vMAJOR.MINOR.PATCH` from a clean checkout.
- [ ] Run `(cd dist && sha256sum --check SHA256SUMS)` and require every archive to pass.
- [ ] Confirm each archive contains only `api_datagram` (or `api_datagram.exe`), `LICENSE`, `README.md`, and `config.example.yaml` under its versioned directory.
- [ ] Run the host-compatible binary with `-version` and confirm version, full commit SHA, and UTC build date.
- [ ] Confirm manual workflow runs upload artifacts but create no GitHub Release.
- [ ] Confirm only a strict semantic-version tag publishes a release.

The release workflow is artifact delivery, not a production deployment. Production rollout remains blocked until target infrastructure, credential handling, health signals, and rollback ownership are defined.
