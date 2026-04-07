package config

import (
	"encoding/json"
	"os"
)

type EmailConfig struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	From     string `json:"from"`
	Password string `json:"password"`
}

type Config struct {
	ServerAddress        string      `json:"server_address"`
	DatabasePath         string      `json:"database_path"`
	SessionLifetimeHours int         `json:"session_lifetime_hours"`
	TLSEnabled           bool        `json:"tls_enabled"`
	TLSCertFile          string      `json:"tls_cert_file"`
	TLSKeyFile           string      `json:"tls_key_file"`
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

	return &cfg, nil
}
