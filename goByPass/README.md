```
mydpi-bypass/
├── cmd/                           # Точки входа в приложение
│   ├── mydpi/                     # Основной CLI инструмент
│   │   └── main.go
│   ├── mydpi-discovery/            # Инструмент автоподбора стратегий
│   │   └── main.go
│   └── mydpi-daemon/               # Фоновый сервис
│       └── main.go
│
├── internal/                       # Внутренняя логика (не для импорта извне)
│   ├── capture/                    # Перехват пакетов
│   │   ├── capture.go              # Интерфейсы
│   │   ├── nfqueue_linux.go        # Реализация для Linux
│   │   └── nfqueue_linux_test.go   # Тесты
│   │
│   ├── modifier/                   # Модификация пакетов
│   │   ├── modifier.go
│   │   ├── split.go                # split-методы
│   │   ├── disorder.go              # disorder-методы
│   │   ├── fake.go                  # fake-методы
│   │   └── tls_split.go            # TLS record splitting
│   │
│   ├── conntrack/                   # Отслеживание потоков
│   │   ├── manager.go
│   │   ├── flow.go
│   │   └── flow_test.go
│   │
│   ├── protocol/                    # Разбор протоколов
│   │   ├── analyzer.go
│   │   ├── tls.go                   # TLS/SNI парсер
│   │   ├── http.go                   # HTTP парсер
│   │   └── protocol_test.go
│   │
│   ├── cache/                       # Кэширование
│   │   ├── ipcache.go
│   │   ├── domaincache.go
│   │   └── cache_test.go
│   │
│   ├── strategy/                    # Стратегии обхода
│   │   ├── manager.go
│   │   ├── strategy.go
│   │   ├── profiles.go              # Готовые профили
│   │   └── discovery.go              # Автоподбор
│   │
│   ├── packetflow/                   # Конвейер обработки
│   │   ├── pipeline.go
│   │   ├── worker.go
│   │   └── pipeline_test.go
│   │
│   ├── sender/                       # Отправка пакетов
│   │   ├── sender.go
│   │   ├── raw_linux.go
│   │   └── raw_windows.go
│   │
│   ├── firewall/                     # Управление файрволом
│   │   ├── iptables.go
│   │   ├── nftables.go
│   │   └── firewall.go
│   │
│   └── config/                       # Конфигурация
│       ├── loader.go
│       ├── validate.go
│       └── defaults.go
│
├── pkg/                              # Публичные пакеты (можно импортировать)
│   ├── api/                          # API для Java (gomobile)
│   │   ├── bindings.go
│   │   └── types.go
│   │
│   └── models/                       # Общие модели данных
│       ├── packet.go
│       ├── flow.go
│       └── strategy.go
│
├── platform/                         # Платформозависимый код
│   ├── linux/
│   │   └── nfqueue_bridge.go         # Cgo обёртки для NFQUEUE
│   ├── windows/
│   │   └── windivert_bridge.go       # Cgo обёртки для WinDivert
│   └── android/
│       └── vpnservice_bridge.go      # Java-вызовы через gomobile
│
├── scripts/                          # Скрипты для сборки и деплоя
│   ├── build.sh
│   ├── build-all.sh
│   ├── test.sh
│   └── docker/
│       └── Dockerfile
│
├── configs/                          # Примеры конфигураций
│   ├── default.yaml
│   ├── strategies/
│   │   ├── aggressive.yaml
│   │   ├── moderate.yaml
│   │   └── discovery.json
│   └── lists/
│       ├── domains.txt
│       └── ips.txt
│
├── test/                             # Интеграционные тесты
│   ├── integration/
│   │   └── dpi_test.go
│   └── e2e/
│       └── zapret_compat_test.go
│
├── docs/                              # Документация
│   ├── architecture.md
│   ├── api.md
│   └── development.md
│
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── LICENSE
```
