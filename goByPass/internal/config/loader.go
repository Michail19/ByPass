package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load загружает конфигурацию из файла
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	// Если файл не указан, возвращаем конфигурацию по умолчанию
	if path == "" {
		return cfg, nil
	}

	// Читаем файл
	data, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, fmt.Errorf("config file not found: %s", path)
		}
		return nil, fmt.Errorf("failed to read config: %v", err)
	}

	// Определяем формат по расширению
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %v", err)
		}
	case ".json":
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config format: %s", ext)
	}

	// Валидируем конфигурацию
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}

	return cfg, nil
}

// LoadFromEnv загружает конфигурацию из переменных окружения
func LoadFromEnv() (*Config, error) {
	cfg := DefaultConfig()

	// Пример: MYDPI_CAPTURE_QUEUE_NUM=1
	// Можно реализовать через github.com/kelseyhightower/envconfig

	return cfg, nil
}

// Save сохраняет конфигурацию в файл
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, data, 0644)
}
