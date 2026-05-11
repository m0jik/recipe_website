// Package config provides functionality for loading and managing application configuration from a JSON file and environment variables.
package config

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
)

type EmailConfig struct {
	Provider string      `json:"provider"`
	SES      *SESConfig  `json:"ses"`
	SMTP     *SMTPConfig `json:"smtp"`
}

type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	From     string `json:"from"`
	Password string `json:"password"`
}

type SESConfig struct {
	From                string `json:"from"`
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

	// f.Close()
	defer func() {
		if err := f.Close(); err != nil {
			log.Println("Error closing config file:", err)
		}
	}()

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
		if cfg.Email.Provider == "smtp" {
			cfg.Email.SMTP.Host = v
		}
	}
	if v := os.Getenv("EMAIL_FROM"); v != "" {
		// if cfg.Email.Provider == "smtp" {
		// 	cfg.Email.SMTP.From = v
		// } else if cfg.Email.Provider == "ses" {
		// 	cfg.Email.SES.From = v
		// }
		switch cfg.Email.Provider {
		case "smtp":
			cfg.Email.SMTP.From = v
		case "ses":
			cfg.Email.SES.From = v
		default:
			log.Printf("Uknown email provider '%s', cannot set 'From' address from environment variable", cfg.Email.Provider)
		}
	}
	if v := os.Getenv("EMAIL_PASSWORD"); v != "" {
		if cfg.Email.Provider == "smtp" {
			cfg.Email.SMTP.Password = v
		}
	}
	if v := os.Getenv("AWS_REGION"); v != "" {
		if cfg.Email.Provider == "ses" {
			cfg.Email.SES.AWSRegion = v
		}
	}
	if v := os.Getenv("AWS_SES_CONFIGURATION_SET"); v != "" {
		if cfg.Email.Provider == "ses" {
			cfg.Email.SES.AWSConfigurationSet = v
		}
	}
	if v := os.Getenv("EMAIL_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			if cfg.Email.Provider == "smtp" {
				cfg.Email.SMTP.Port = p
			}
		}
	}
}
