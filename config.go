package main

import (
    "errors"
    "fmt"
    "net/url"
    "strings"
    "time"

    "github.com/kelseyhightower/envconfig"
)

type Secret string

func (s Secret) String() string   { return "***" }
func (s Secret) GoString() string { return "***" }
func (s Secret) Value() string    { return string(s) }
func (s Secret) IsEmpty() bool    { return len(s) == 0 }

const minSecretLen = 32

type Config struct {
    Host string `envconfig:"COORDINATOR_HOST" default:"0.0.0.0"`
    Port int    `envconfig:"COORDINATOR_PORT" default:"8080"`

    RedisURL string `envconfig:"REDIS_URL" required:"true"`

    HMACSecret Secret `envconfig:"HMAC_SECRET" required:"true"`
    AdminToken Secret `envconfig:"ADMIN_TOKEN" required:"true"`

    DefaultDomain   string `envconfig:"DEFAULT_DOMAIN"   required:"true"`
    DefaultRedirect string `envconfig:"DEFAULT_REDIRECT" required:"true"`

    UpdateInterval int `envconfig:"UPDATE_INTERVAL" default:"300"`
    RedisTTL       int `envconfig:"REDIS_TTL"       default:"3600"`

    LogLevel    string `envconfig:"LOG_LEVEL"`
    TLSCertFile string `envconfig:"TLS_CERT_FILE"`
    TLSKeyFile  string `envconfig:"TLS_KEY_FILE"`

    AdminAllowedIPs []string `envconfig:"ADMIN_ALLOWED_IPS"`
}

func (c *Config) UpdateIntervalDuration() time.Duration {
    return time.Duration(c.UpdateInterval) * time.Second
}

func (c *Config) RedisTTLDuration() time.Duration {
    return time.Duration(c.RedisTTL) * time.Second
}

func (c *Config) ListenAddr() string {
    return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func Load() (*Config, error) {
    var cfg Config
    if err := envconfig.Process("", &cfg); err != nil {
        return nil, fmt.Errorf("config: parse env: %w", err)
    }
    if err := cfg.validate(); err != nil {
        return nil, fmt.Errorf("config: validation: %w", err)
    }
    return &cfg, nil
}

func (c *Config) validate() error {
    var errs []string

    if c.Port < 1 || c.Port > 65535 {
        errs = append(errs, fmt.Sprintf("COORDINATOR_PORT must be 1-65535, got %d", c.Port))
    }
    if c.HMACSecret.IsEmpty() {
        errs = append(errs, "HMAC_SECRET must not be empty")
    } else if len(c.HMACSecret.Value()) < minSecretLen {
        errs = append(errs, fmt.Sprintf("HMAC_SECRET must be at least %d characters", minSecretLen))
    }
    if c.AdminToken.IsEmpty() {
        errs = append(errs, "ADMIN_TOKEN must not be empty")
    } else if len(c.AdminToken.Value()) < minSecretLen {
        errs = append(errs, fmt.Sprintf("ADMIN_TOKEN must be at least %d characters", minSecretLen))
    }
    if err := validateURL(c.DefaultRedirect); err != nil {
        errs = append(errs, fmt.Sprintf("DEFAULT_REDIRECT: %s", err))
    }
    if c.UpdateInterval < 1 {
        errs = append(errs, fmt.Sprintf("UPDATE_INTERVAL must be >= 1, got %d", c.UpdateInterval))
    }
    if c.RedisTTL < 1 {
        errs = append(errs, fmt.Sprintf("REDIS_TTL must be >= 1, got %d", c.RedisTTL))
    }
    if strings.TrimSpace(c.DefaultDomain) == "" {
        errs = append(errs, "DEFAULT_DOMAIN must not be empty")
    }

    validLevels := map[string]bool{
        "debug": true, "info": true, "warn": true, "error": true,
    }
    if !validLevels[strings.ToLower(c.LogLevel)] {
        errs = append(errs, fmt.Sprintf("LOG_LEVEL must be debug/info/warn/error, got %q", c.LogLevel))
    }

    if len(errs) > 0 {
        return errors.New(strings.Join(errs, "; "))
    }
    return nil
}

func validateURL(s string) error {
    if strings.TrimSpace(s) == "" {
        return errors.New("must not be empty")
    }
    u, err := url.ParseRequestURI(s)
    if err != nil {
        return fmt.Errorf("must be a valid URL: %w", err)
    }
    if u.Scheme != "http" && u.Scheme != "https" {
        return fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
    }
    if u.Host == "" {
        return errors.New("must contain a host")
    }
    return nil
}
