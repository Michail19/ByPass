# Makefile for ByPass DPI Bypass

# ============================================================================
# Метопеременные
# ============================================================================
APP_NAME = bypass
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GO_VERSION ?= $(shell go version | cut -d' ' -f3 | sed 's/go//')

# Флаги линковки для внедрения версии
LDFLAGS = -ldflags "\
	-X main.version=$(VERSION) \
	-X main.buildTime=$(BUILD_TIME) \
	-X main.commit=$(COMMIT) \
	-w -s"

# Платформы для кросс-компиляции
PLATFORMS = linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64

# Директории
BIN_DIR = bin
CONFIG_DIR = /etc/$(APP_NAME)
LOG_DIR = /var/log/$(APP_NAME)
SYSTEMD_DIR = /etc/systemd/system

# Цвета для вывода
GREEN = \033[0;32m
YELLOW = \033[0;33m
RED = \033[0;31m
NC = \033[0m # No Color

# ============================================================================
# Основные цели
# ============================================================================

.PHONY: all
all: clean deps lint test build ## Выполнить полную сборку (очистка, зависимости, линтинг, тесты, сборка)

.PHONY: help
help: ## Показать эту справку
	@printf "$(YELLOW)Available targets:$(NC)\n"
	@awk 'BEGIN {FS = ":.*##"; printf "\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ============================================================================
# Сборка
# ============================================================================

.PHONY: build
build: ## Собрать для текущей платформы
	@printf "$(GREEN)==> Building $(APP_NAME) for $(GOOS)/$(GOARCH)...$(NC)\n"
	mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME) cmd/$(APP_NAME)/main.go
	go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-discovery cmd/mydpi-discovery/main.go
	go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-daemon cmd/mydpi-daemon/main.go
	@printf "$(GREEN)==> Build complete! Binaries in $(BIN_DIR)/$(NC)\n"

.PHONY: build-linux
build-linux: ## Собрать для Linux (amd64)
	@printf "$(GREEN)==> Building for Linux amd64...$(NC)\n"
	mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-linux-amd64 cmd/$(APP_NAME)/main.go
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-discovery-linux-amd64 cmd/mydpi-discovery/main.go
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-daemon-linux-amd64 cmd/mydpi-daemon/main.go

.PHONY: build-linux-arm
build-linux-arm: ## Собрать для Linux (arm64)
	@printf "$(GREEN)==> Building for Linux arm64...$(NC)\n"
	mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-linux-arm64 cmd/$(APP_NAME)/main.go
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-discovery-linux-arm64 cmd/mydpi-discovery/main.go
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-daemon-linux-arm64 cmd/mydpi-daemon/main.go

.PHONY: build-windows
build-windows: ## Собрать для Windows (amd64)
	@printf "$(GREEN)==> Building for Windows amd64...$(NC)\n"
	mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-windows-amd64.exe cmd/$(APP_NAME)/main.go
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-discovery-windows-amd64.exe cmd/mydpi-discovery/main.go
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-daemon-windows-amd64.exe cmd/mydpi-daemon/main.go

.PHONY: build-windows-arm
build-windows-arm: ## Собрать для Windows (arm64)
	@printf "$(GREEN)==> Building for Windows arm64...$(NC)\n"
	mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-windows-arm64.exe cmd/$(APP_NAME)/main.go
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-discovery-windows-arm64.exe cmd/mydpi-discovery/main.go
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-daemon-windows-arm64.exe cmd/mydpi-daemon/main.go

.PHONY: build-darwin
build-darwin: ## Собрать для macOS (amd64)
	@printf "$(GREEN)==> Building for macOS amd64...$(NC)\n"
	mkdir -p $(BIN_DIR)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-darwin-amd64 cmd/$(APP_NAME)/main.go
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-discovery-darwin-amd64 cmd/mydpi-discovery/main.go
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-daemon-darwin-amd64 cmd/mydpi-daemon/main.go

.PHONY: build-darwin-arm
build-darwin-arm: ## Собрать для macOS (arm64/M1)
	@printf "$(GREEN)==> Building for macOS arm64...$(NC)\n"
	mkdir -p $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-darwin-arm64 cmd/$(APP_NAME)/main.go
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-discovery-darwin-arm64 cmd/mydpi-discovery/main.go
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(APP_NAME)-daemon-darwin-arm64 cmd/mydpi-daemon/main.go

.PHONY: build-all
build-all: clean build-linux build-linux-arm build-windows build-windows-arm build-darwin build-darwin-arm ## Собрать для всех платформ
	@printf "$(GREEN)==> All builds completed!$(NC)\n"
	@ls -la $(BIN_DIR)/

.PHONY: build-mobile
build-mobile: ## Собрать мобильную библиотеку (Android)
	@printf "$(GREEN)==> Building Android library...$(NC)\n"
	mkdir -p $(BIN_DIR)
	gomobile bind -target=android -o $(BIN_DIR)/$(APP_NAME).aar ./pkg/api
	@printf "$(GREEN)==> Android library built: $(BIN_DIR)/$(APP_NAME).aar$(NC)\n"

# ============================================================================
# Зависимости
# ============================================================================

.PHONY: deps
deps: ## Установить зависимости
	@printf "$(GREEN)==> Downloading dependencies...$(NC)\n"
	go mod download
	go mod verify

.PHONY: tidy
tidy: ## Очистить и упорядочить go.mod
	@printf "$(GREEN)==> Tidying go.mod...$(NC)\n"
	go mod tidy

.PHONY: vendor
vendor: ## Создать vendor директорию
	@printf "$(GREEN)==> Vendoring dependencies...$(NC)\n"
	go mod vendor

.PHONY: update-deps
update-deps: ## Обновить все зависимости
	@printf "$(GREEN)==> Updating dependencies...$(NC)\n"
	go get -u ./...
	go mod tidy

# ============================================================================
# Тестирование и линтинг
# ============================================================================

.PHONY: test
test: ## Запустить тесты
	@printf "$(GREEN)==> Running tests...$(NC)\n"
	go test -v -cover -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

.PHONY: test-race
test-race: ## Запустить тесты с детектором гонок
	@printf "$(GREEN)==> Running tests with race detector...$(NC)\n"
	go test -race -v ./...

.PHONY: test-short
test-short: ## Запустить короткие тесты
	@printf "$(GREEN)==> Running short tests...$(NC)\n"
	go test -short -v ./...

.PHONY: bench
bench: ## Запустить бенчмарки
	@printf "$(GREEN)==> Running benchmarks...$(NC)\n"
	go test -bench=. -benchmem ./...

.PHONY: lint
lint: ## Запустить линтер (golangci-lint)
	@printf "$(GREEN)==> Running linter...$(NC)\n"
	command -v golangci-lint >/dev/null 2>&1 || { \
		printf "$(RED)golangci-lint not installed. Installing...$(NC)\n"; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.55.2; \
	}
	golangci-lint run ./...

.PHONY: fmt
fmt: ## Форматировать код
	@printf "$(GREEN)==> Formatting code...$(NC)\n"
	go fmt ./...

.PHONY: vet
vet: ## Запустить go vet
	@printf "$(GREEN)==> Running go vet...$(NC)\n"
	go vet ./...

.PHONY: check
check: fmt vet lint test ## Запустить все проверки

# ============================================================================
# Очистка
# ============================================================================

.PHONY: clean
clean: ## Очистить бинарники и временные файлы
	@printf "$(GREEN)==> Cleaning...$(NC)\n"
	rm -rf $(BIN_DIR)/
	rm -f coverage.out coverage.html
	go clean -cache -testcache -modcache

.PHONY: clean-all
clean-all: clean ## Полная очистка (включая vendor)
	rm -rf vendor/

# ============================================================================
# Установка и развертывание
# ============================================================================

.PHONY: install
install: build ## Установить в систему (Linux)
	@printf "$(GREEN)==> Installing to system...$(NC)\n"
	# Проверяем, что мы на Linux
	@if [ "$(shell uname)" != "Linux" ]; then \
		printf "$(RED)Install target is only for Linux$(NC)\n"; \
		exit 1; \
	fi
	# Создаем директории
	sudo mkdir -p $(CONFIG_DIR)
	sudo mkdir -p $(CONFIG_DIR)/strategies
	sudo mkdir -p $(CONFIG_DIR)/lists
	sudo mkdir -p $(LOG_DIR)

	# Копируем бинарники
	sudo cp $(BIN_DIR)/$(APP_NAME) /usr/local/bin/
	sudo cp $(BIN_DIR)/$(APP_NAME)-discovery /usr/local/bin/
	sudo cp $(BIN_DIR)/$(APP_NAME)-daemon /usr/local/bin/

	# Копируем конфиги (если есть)
	@if [ -d "configs" ]; then \
		sudo cp configs/default.yaml $(CONFIG_DIR)/ 2>/dev/null || true; \
		sudo cp -r configs/strategies/* $(CONFIG_DIR)/strategies/ 2>/dev/null || true; \
		sudo cp -r configs/lists/* $(CONFIG_DIR)/lists/ 2>/dev/null || true; \
	fi

	# Устанавливаем права
	sudo chmod +x /usr/local/bin/$(APP_NAME)*

	@printf "$(GREEN)==> Installation complete!$(NC)\n"
	@printf "$(GREEN)==> Binaries in /usr/local/bin/$(NC)\n"
	@printf "$(GREEN)==> Configs in $(CONFIG_DIR)/$(NC)\n"

.PHONY: uninstall
uninstall: ## Удалить из системы
	@printf "$(GREEN)==> Uninstalling...$(NC)\n"
	sudo rm -f /usr/local/bin/$(APP_NAME)
	sudo rm -f /usr/local/bin/$(APP_NAME)-discovery
	sudo rm -f /usr/local/bin/$(APP_NAME)-daemon
	sudo rm -rf $(CONFIG_DIR)
	sudo rm -rf $(LOG_DIR)
	@printf "$(GREEN)==> Uninstallation complete!$(NC)\n"

.PHONY: install-systemd
install-systemd: ## Установить systemd сервис
	@printf "$(GREEN)==> Installing systemd service...$(NC)\n"
	@if [ ! -f /usr/local/bin/$(APP_NAME) ]; then \
		printf "$(RED)Binary not found. Run 'make install' first.$(NC)\n"; \
		exit 1; \
	fi

	# Создаем systemd unit файл
	sudo tee $(SYSTEMD_DIR)/$(APP_NAME).service > /dev/null << EOF
[Unit]
Description=ByPass DPI Bypass Service
Documentation=https://github.com/yourusername/ByPass
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/$(APP_NAME) -config $(CONFIG_DIR)/config.yaml
Restart=always
RestartSec=10
StandardOutput=append:$(LOG_DIR)/out.log
StandardError=append:$(LOG_DIR)/err.log

[Install]
WantedBy=multi-user.target
EOF

	sudo systemctl daemon-reload
	@printf "$(GREEN)==> Systemd service installed!$(NC)\n"
	@printf "$(GREEN)==> Run: sudo systemctl start $(APP_NAME)$(NC)\n"

.PHONY: install-docker
install-docker: ## Собрать Docker образ
	@printf "$(GREEN)==> Building Docker image...$(NC)\n"
	docker build -t $(APP_NAME):$(VERSION) -f scripts/docker/Dockerfile .
	docker tag $(APP_NAME):$(VERSION) $(APP_NAME):latest
	@printf "$(GREEN)==> Docker image built: $(APP_NAME):$(VERSION)$(NC)\n"

# ============================================================================
# Запуск
# ============================================================================

.PHONY: run
run: build ## Запустить приложение (требуются root права)
	@printf "$(GREEN)==> Running $(APP_NAME)...$(NC)\n"
	sudo $(BIN_DIR)/$(APP_NAME) -config configs/default.yaml

.PHONY: run-discovery
run-discovery: build ## Запустить авто-дискавери
	@printf "$(GREEN)==> Running discovery...$(NC)\n"
	$(BIN_DIR)/$(APP_NAME)-discovery -config configs/default.yaml

.PHONY: run-daemon
run-daemon: build ## Запустить демон
	@printf "$(GREEN)==> Running daemon...$(NC)\n"
	sudo $(BIN_DIR)/$(APP_NAME)-daemon -config configs/default.yaml

.PHONY: run-with-params
run-with-params: build ## Запустить с параметрами (используйте ARGS="...")
	@printf "$(GREEN)==> Running with args: $(ARGS)$(NC)\n"
	sudo $(BIN_DIR)/$(APP_NAME) $(ARGS)

# ============================================================================
# Утилиты
# ============================================================================

.PHONY: version
version: ## Показать версию
	@printf "$(GREEN)==> Version: $(VERSION)$(NC)\n"
	@printf "$(GREEN)==> Commit: $(COMMIT)$(NC)\n"
	@printf "$(GREEN)==> Build time: $(BUILD_TIME)$(NC)\n"
	@printf "$(GREEN)==> Go version: $(GO_VERSION)$(NC)\n"

.PHONY: info
info: ## Показать информацию о проекте
	@printf "$(GREEN)==> Project info:$(NC)\n"
	@printf "  App name: $(APP_NAME)\n"
	@printf "  Version: $(VERSION)\n"
	@printf "  Commit: $(COMMIT)\n"
	@printf "  Build time: $(BUILD_TIME)\n"
	@printf "  Go version: $(GO_VERSION)\n"
	@printf "  Platforms: $(PLATFORMS)\n"

.PHONY: generate-config
generate-config: ## Сгенерировать конфиг по умолчанию
	@printf "$(GREEN)==> Generating default config...$(NC)\n"
	mkdir -p configs
	$(BIN_DIR)/$(APP_NAME) -gen-config configs/default.yaml

.PHONY: check-root
check-root: ## Проверить root права
	@if [ "$$EUID" -ne 0 ]; then \
		printf "$(RED)This command requires root privileges. Run with sudo.$(NC)\n"; \
		exit 1; \
	fi

.PHONY: git-hooks
git-hooks: ## Установить git хуки
	@printf "$(GREEN)==> Installing git hooks...$(NC)\n"
	@mkdir -p .git/hooks
	@printf '#!/bin/sh\nmake fmt lint test\n' > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@printf "$(GREEN)==> Git hooks installed!$(NC)\n"

# ============================================================================
# Документация
# ============================================================================

.PHONY: docs
docs: ## Сгенерировать документацию
	@printf "$(GREEN)==> Generating documentation...$(NC)\n"
	godoc -http=:6060 &
	@printf "$(GREEN)==> Documentation available at http://localhost:6060/pkg/$(APP_NAME)/$(NC)\n"

# ============================================================================
# Дефолтная цель
# ============================================================================

.DEFAULT_GOAL := help
