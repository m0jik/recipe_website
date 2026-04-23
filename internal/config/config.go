package config

import (
	"encoding/json"
	"os"
)

type EmailConfig struct {
	Provider            string `json:"provider"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	From                string `json:"from"`
	Password            string `json:"password"`
	AWSRegion           string `json:"aws_region"`
	AWSConfigurationSet string `json:"aws_configuration_set"`
}

type Config struct {
	ServerAddress        string      `json:"server_address"`
	DatabasePath         string      `json:"database_path"`
	SessionLifetimeHours int         `json:"session_lifetime_hours"`
	TLSEnabled           bool        `json:"tls_enabled"`
	TLSCertFile          string      `json:"tls_cert_file"`
	TLSKeyFile           string      `json:"tls_key_file"`
	BaseURL              string      `json:"base_url"`
	Email                EmailConfig `json:"email"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}

	applyEnvOverrides(&cfg)

	if cfg.Email.Provider == "" {
		cfg.Email.Provider = "smtp"
	}

	return &cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("SERVER_ADDRESS"); v != "" {
		cfg.ServerAddress = v
	}
	if v := os.Getenv("DATABASE_PATH"); v != "" {
		cfg.DatabasePath = v
	}
	if v := os.Getenv("BASE_URL"); v != "" {
		cfg.BaseURL = v
	}
	if v := os.Getenv("EMAIL_PROVIDER"); v != "" {
		cfg.Email.Provider = v
	}
	if v := os.Getenv("EMAIL_HOST"); v != "" {
		cfg.Email.Host = v
	}
	if v := os.Getenv("EMAIL_FROM"); v != "" {
		cfg.Email.From = v
	}
	if v := os.Getenv("EMAIL_PASSWORD"); v != "" {
		cfg.Email.Password = v
	}
	if v := os.Getenv("AWS_REGION"); v != "" {
		cfg.Email.AWSRegion = v
	}
	if v := os.Getenv("AWS_SES_CONFIGURATION_SET"); v != "" {
		cfg.Email.AWSConfigurationSet = v
	}
}
