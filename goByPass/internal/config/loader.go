package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load загружает конфигурацию из файла.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	// Если файл не указан — возвращаем конфиг по умолчанию.
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, fmt.Errorf("config file not found: %s", path)
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	case ".json":
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config format: %s", filepath.Ext(path))
	}

	// Нормализуем относительные пути относительно директории самого конфига.
	cfg.resolveRelativePaths(filepath.Dir(path))

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// LoadFromEnv загружает конфигурацию из переменных окружения.
// Пока оставлен как заглушка.
func LoadFromEnv() (*Config, error) {
	cfg := DefaultConfig()
	return cfg, nil
}

// Save сохраняет конфигурацию в файл.
func (c *Config) Save(path string) error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}

	var (
		data []byte
		err  error
	)

	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", "":
		data, err = yaml.Marshal(c)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML: %w", err)
		}
	case ".json":
		data, err = json.MarshalIndent(c, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
	default:
		return fmt.Errorf("unsupported config format for save: %s", filepath.Ext(path))
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create config directory %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// resolveRelativePaths приводит относительные пути к абсолютным относительно папки конфига.
func (c *Config) resolveRelativePaths(baseDir string) {
	baseDir = strings.TrimSpace(baseDir)
	if baseDir == "" {
		baseDir = "."
	}

	if strings.TrimSpace(c.Strategy.StrategyFile) != "" && !filepath.IsAbs(c.Strategy.StrategyFile) {
		c.Strategy.StrategyFile = filepath.Clean(filepath.Join(baseDir, c.Strategy.StrategyFile))
	}

	if c.Logging.Output == "file" &&
		strings.TrimSpace(c.Logging.FilePath) != "" &&
		!filepath.IsAbs(c.Logging.FilePath) {
		c.Logging.FilePath = filepath.Clean(filepath.Join(baseDir, c.Logging.FilePath))
	}
}
