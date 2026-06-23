package main

import (
    "strings"
	"time"
    "testing"
)

func validEnv(t *testing.T, overrides map[string]string) {
    t.Helper()
    base := map[string]string{
        "REDIS_URL":        "redis://localhost:6379/0",
        "HMAC_SECRET": "this-is-a-32-character-secret!!!",
"ADMIN_TOKEN": "this-is-a-32-character-secret!!!",
        "DEFAULT_DOMAIN":   "example.com",
        "DEFAULT_REDIRECT": "https://rn.example.com",
    }
    for k, v := range overrides {
        base[k] = v
    }
    for k, v := range base {
        t.Setenv(k, v)
    }
}

func TestLoad_Defaults(t *testing.T) {
    validEnv(t, nil)

    cfg, err := Load()
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if cfg.Port != 8080 {
        t.Errorf("Port: want 8080, got %d", cfg.Port)
    }
    if cfg.Host != "0.0.0.0" {
        t.Errorf("Host: want 0.0.0.0, got %s", cfg.Host)
    }
    if cfg.UpdateInterval != 300 {
        t.Errorf("UpdateInterval: want 300, got %d", cfg.UpdateInterval)
    }
}

func TestLoad_SecretNotLeaked(t *testing.T) {
    validEnv(t, nil)

    cfg, err := Load()
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if cfg.HMACSecret.String() != "***" {
        t.Errorf("Secret.String() leaked value")
    }
    if cfg.HMACSecret.GoString() != "***" {
        t.Errorf("Secret.GoString() leaked value")
    }
    if cfg.HMACSecret.Value() == "" {
        t.Error("Secret.Value() returned empty string")
    }
}

var validationCases = []struct {
    name    string
    env     map[string]string
    wantErr string
}{
    {
        name:    "invalid port - too low",
        env:     map[string]string{"COORDINATOR_PORT": "0"},
        wantErr: "COORDINATOR_PORT",
    },
    {
        name:    "invalid port - too high",
        env:     map[string]string{"COORDINATOR_PORT": "99999"},
        wantErr: "COORDINATOR_PORT",
    },
    {
        name:    "secret too short",
        env:     map[string]string{"HMAC_SECRET": "short"},
        wantErr: "HMAC_SECRET",
    },
    {
        name:    "invalid redirect - no scheme",
        env:     map[string]string{"DEFAULT_REDIRECT": "not-a-url"},
        wantErr: "DEFAULT_REDIRECT",
    },
    {
        name:    "invalid redirect - ftp scheme",
        env:     map[string]string{"DEFAULT_REDIRECT": "ftp://example.com"},
        wantErr: "DEFAULT_REDIRECT",
    },
    {
        name:    "negative update interval",
        env:     map[string]string{"UPDATE_INTERVAL": "-1"},
        wantErr: "UPDATE_INTERVAL",
    },
    {
        name:    "zero redis ttl",
        env:     map[string]string{"REDIS_TTL": "0"},
        wantErr: "REDIS_TTL",
    },
}

func TestLoad_Validation(t *testing.T) {
    for _, tc := range validationCases {
        t.Run(tc.name, func(t *testing.T) {
            validEnv(t, tc.env)

            _, err := Load()
            if err == nil {
                t.Fatal("expected error, got nil")
            }
            if !strings.Contains(err.Error(), tc.wantErr) {
                t.Errorf("error %q does not mention %q", err.Error(), tc.wantErr)
            }
        })
    }
}

func TestListenAddr(t *testing.T) {
    validEnv(t, map[string]string{
        "COORDINATOR_HOST": "127.0.0.1",
        "COORDINATOR_PORT": "9090",
    })

    cfg, err := Load()
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if cfg.ListenAddr() != "127.0.0.1:9090" {
        t.Errorf("ListenAddr: want 127.0.0.1:9090, got %s", cfg.ListenAddr())
    }
}
func TestUpdateIntervalDuration(t *testing.T) {
    validEnv(t, map[string]string{"UPDATE_INTERVAL": "60"})
    cfg, err := Load()
    if err != nil {
        t.Fatalf("Load: %v", err)
    }
    if cfg.UpdateIntervalDuration() != 60*time.Second {
        t.Errorf("UpdateIntervalDuration: want 60s, got %v", cfg.UpdateIntervalDuration())
    }
}

func TestRedisTTLDuration(t *testing.T) {
    validEnv(t, map[string]string{"REDIS_TTL": "120"})
    cfg, err := Load()
    if err != nil {
        t.Fatalf("Load: %v", err)
    }
    if cfg.RedisTTLDuration() != 120*time.Second {
        t.Errorf("RedisTTLDuration: want 120s, got %v", cfg.RedisTTLDuration())
    }
}

func TestLoad_EnvProcessError(t *testing.T) {
    // COORDINATOR_PORT не является числом — envconfig вернёт ошибку
    t.Setenv("COORDINATOR_PORT", "not-a-number")
    t.Setenv("REDIS_URL", "redis://localhost:6379/0")
    t.Setenv("HMAC_SECRET", "this-is-a-32-character-secret!!!")
    t.Setenv("ADMIN_TOKEN", "this-is-a-32-character-secret!!!")
    t.Setenv("DEFAULT_DOMAIN", "example.com")
    t.Setenv("DEFAULT_REDIRECT", "https://rn.example.com")
    _, err := Load()
    if err == nil {
        t.Error("expected error for invalid port type, got nil")
    }
}

func TestValidate_AdminTokenShort(t *testing.T) {
    validEnv(t, map[string]string{"ADMIN_TOKEN": "short"})
    _, err := Load()
    if err == nil || !strings.Contains(err.Error(), "ADMIN_TOKEN") {
        t.Errorf("expected ADMIN_TOKEN error, got %v", err)
    }
}

func TestValidate_DefaultDomainEmpty(t *testing.T) {
    validEnv(t, map[string]string{"DEFAULT_DOMAIN": "   "})
    _, err := Load()
    if err == nil || !strings.Contains(err.Error(), "DEFAULT_DOMAIN") {
        t.Errorf("expected DEFAULT_DOMAIN error, got %v", err)
    }
}

func TestValidate_InvalidLogLevel(t *testing.T) {
    validEnv(t, map[string]string{"LOG_LEVEL": "verbose"})
    _, err := Load()
    if err == nil || !strings.Contains(err.Error(), "LOG_LEVEL") {
        t.Errorf("expected LOG_LEVEL error, got %v", err)
    }
}

func TestValidateURL_EmptyString(t *testing.T) {
    validEnv(t, map[string]string{"DEFAULT_REDIRECT": "   "})
    _, err := Load()
    if err == nil || !strings.Contains(err.Error(), "DEFAULT_REDIRECT") {
        t.Errorf("expected DEFAULT_REDIRECT error, got %v", err)
    }
}

func TestValidateURL_EmptyHost(t *testing.T) {
    validEnv(t, map[string]string{"DEFAULT_REDIRECT": "https://"})
    _, err := Load()
    if err == nil || !strings.Contains(err.Error(), "DEFAULT_REDIRECT") {
        t.Errorf("expected DEFAULT_REDIRECT empty host error, got %v", err)
    }
}

func TestValidate_HMACSecretEmpty(t *testing.T) {
    validEnv(t, map[string]string{"HMAC_SECRET": ""})
    _, err := Load()
    if err == nil || !strings.Contains(err.Error(), "HMAC_SECRET") {
        t.Errorf("expected HMAC_SECRET error, got %v", err)
    }
}

func TestValidate_AdminTokenEmpty(t *testing.T) {
    validEnv(t, map[string]string{"ADMIN_TOKEN": ""})
    _, err := Load()
    if err == nil || !strings.Contains(err.Error(), "ADMIN_TOKEN") {
        t.Errorf("expected ADMIN_TOKEN error, got %v", err)
    }
}
