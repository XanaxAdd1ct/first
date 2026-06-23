// рackage main точка входа координатора
// конфиг намеренно плоский  никаких вложенных структур
// всё приходит из окружения  никаких yaml toml json файлов
// причина простая  секреты не должны лежать в файлах рядом с кодом

package main

import (
    "errors"
    "fmt"
    "net/url"
    "strings"
    "time"

    "github.com/kelseyhightower/envconfig"
)

// Secret это обёртка над строкой для хранения чувствительных данных
//
// главная цель  не дать секрету утечь в логи или трейсы
// fmt.Sprintf("%v", secret) вернёт "***"  GoString() тоже
// реальное значение достать можно только явно через Value()
//
// использование намеренно неудобное  это фича не баг

type Secret string

// Config вся конфигурация сервиса
//
// теги envconfig покрывают и парсинг и документацию одновременно
// смотришь на структуру и сразу видишь какие переменные нужны
//
// required:"true" означает что процесс упадёт при старте если переменная
// не задана  лучше падать сразу чем получать странные ошибки в рантайме

func (s Secret) String() string   { return "***" }
func (s Secret) GoString() string { return "***" }
func (s Secret) Value() string    { return string(s) }
func (s Secret) IsEmpty() bool    { return len(s) == 0 }

type Config struct {
     // Host и Port разделены специально  удобнее в k8s и docker-compose
    // где часто нужно биндить только на определённый интерфейс
    Host string `envconfig:"COORDINATOR_HOST" default:"0.0.0.0"`
    Port int    `envconfig:"COORDINATOR_PORT" default:"8080"`

    RedisURL string `envconfig:"REDIS_URL" required:"true"`

    // HMACSecret используется для подписи payload-ов агентам
    // при ротации старый секрет живёт ещё keyGracePeriod (1h)
    // агенты успевают получить ответы подписанные старым ключом
    HMACSecret Secret `envconfig:"HMAC_SECRET" required:"true"`

    // AdminToken это Bearer токен для /admin/* эндпоинтов
    // минимум 32 символа  проверяется в validate()
    AdminToken Secret `envconfig:"ADMIN_TOKEN" required:"true"`

    // DefaultDomain и DefaultRedirect используются при первом старте
    // когда в Redis ещё нет конфига  после первого UpdateDomain они
    // больше не используются
    DefaultDomain   string `envconfig:"DEFAULT_DOMAIN"   required:"true"`
    DefaultRedirect string `envconfig:"DEFAULT_REDIRECT" required:"true"`

    // UpdateInterval как часто агенты должны поллить /checkin в секундах
    // передаётся агентам для self-регуляции  сам координатор его не использует
    UpdateInterval int `envconfig:"UPDATE_INTERVAL" default:"300"`

    // RedisTTL это ttl записи конфига в Redis
    // на случай если Redis переживёт координатор  данные сами протухнут
    RedisTTL int `envconfig:"REDIS_TTL" default:"3600"`

    LogLevel string `envconfig:"LOG_LEVEL" default:"info"`
}


// UpdateIntervalDuration возвращает UpdateInterval как time.Duration
// удобнее чем каждый раз писать time.Duration(cfg.UpdateInterval) * time.Second

func (c *Config) UpdateIntervalDuration() time.Duration {
    return time.Duration(c.UpdateInterval) * time.Second
}


// RedisTTLDuration аналогично  конвертация для передачи в storage

func (c *Config) RedisTTLDuration() time.Duration {
    return time.Duration(c.RedisTTL) * time.Second
}

// ListenAddr собирает адрес для http.Server.Addr
// отдельный метод чтобы не собирать строку в нескольких местах

func (c *Config) ListenAddr() string {
    return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

const minSecretLen = 32


// Load читает конфигурацию из переменных окружения и валидирует её

// если хоть одна required переменная не задана или не проходит валидацию
// возвращает ошибку со списком всех проблем сразу а не первой попавшейся
// это важно  лучше увидеть все 5 проблем за раз чем исправлять их по одной

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


// validate проверяет бизнес правила которые нельзя выразить тегами envconfig
//
// проверяет:
//   - COORDINATOR_PORT в диапазоне 1-65535
//   - HMAC_SECRET и ADMIN_TOKEN минимум 32 символа
//   - DEFAULT_REDIRECT валидный http/https URL
//   - DEFAULT_DOMAIN не пустой
//   - UPDATE_INTERVAL и REDIS_TTL больше нуля
//   - LOG_LEVEL один из debug info warn error
//
// собирает все ошибки в слайс и возвращает их одной строкой
// оператору не придётся перезапускать сервис несколько раз

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

// validateURL отдельная функция а не метод  потому что используется
// и в Config.validate()  и в api.go для валидации входящих запросов

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
