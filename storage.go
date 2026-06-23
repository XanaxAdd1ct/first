// слой хранения состояния домена в Redis
//
// весь state сервиса  одна json запись в Redis под ключом "domain_config"
// намеренно простая модель  не нужна история версий  не нужны несколько
// конфигов одновременно  одна запись  один ключ  один ttl



package main

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "time"

    "github.com/go-redis/redis/v8"
)


// domainConfigKey единственный ключ в Redis
// выделен в константу а не хардкод в методах  проще искать при отладке
// и не опечататься при написании тестов

const domainConfigKey = "domain_config"

// ErrNotFound возвращается когда конфига в Redis ещё нет
// отдельная sentinel ошибка  caller может явно обработать первый старт
// через errors.Is(err, ErrNotFound) не разбирая строку ошибки

var ErrNotFound = errors.New("storage: domain config not found")

// ErrVersionConflict возвращается когда WATCH зафиксировал конкурентное изменение
// caller должен повторить операцию  это нормальная ситуация при высокой нагрузке

var ErrVersionConflict = errors.New("storage: version conflict, retry")

// DomainConfig единственная сущность которую хранит координатор
//
// Version монотонно растёт при каждом UpdateDomain
// агенты используют ее чтобы понять получили ли они уже этот апдейт
// если version в ответе совпадает с тем что у них есть  можно ничего не делать

type DomainConfig struct {
    PrimaryDomain  string    `json:"primary_domain"`
    RedirectTarget string    `json:"redirect_target"`
    Version        int64     `json:"version"`
    UpdatedAt      time.Time `json:"updated_at"`
}

// Storage интерфейс для тестируемости
//
// в production используется RedisStorage  в тестах miniredis
// интерфейс намеренно минимальный  только то что реально нужно хендлерам
// Ping отдельным методом  нужен для /health без доп логики

type Storage interface {
    GetDomain(ctx context.Context) (*DomainConfig, error)
    UpdateDomain(ctx context.Context, cfg *DomainConfig) (*DomainConfig, error)
    Ping(ctx context.Context) error
    Close() error
}

// RedisStorage реализует Storage поверх go-redis
//
// ttl это время жизни записи в Redis  выставляется при каждом Set
// если координатор умрёт и не запишет новый конфиг  старый протухнет
// и агенты получат ErrNotFound  что лучше чем работать с устаревшим конфигом вечно

type RedisStorage struct {
    rdb *redis.Client
    ttl time.Duration
}

// NewStorage создаёт и валидирует подключение к Redis
//
// делает Ping при инициализации  fail fast
// лучше упасть при старте с понятной ошибкой чем получить
// connection refused на первом же запросе агента в production

func NewStorage(redisURL string, ttl time.Duration) (*RedisStorage, error) {
    if redisURL == "" {
        return nil, errors.New("storage: redis URL must not be empty")
    }
    if ttl <= 0 {
        return nil, errors.New("storage: ttl must be positive")
    }

    opt, err := redis.ParseURL(redisURL)
    if err != nil {
        return nil, fmt.Errorf("storage: parse redis url: %w", err)
    }

    rdb := redis.NewClient(opt)

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    if err := rdb.Ping(ctx).Err(); err != nil {
        return nil, fmt.Errorf("storage: redis ping: %w", err)
    }

    return &RedisStorage{rdb: rdb, ttl: ttl}, nil
}

// GetDomain читает текущий конфиг домена из Redis
//
// возвращает ErrNotFound если ключа нет  первый старт сервиса
// все остальные ошибки Redis пробрасываются наверх

func (s *RedisStorage) Close() error {
    return s.rdb.Close()
}

func (s *RedisStorage) Ping(ctx context.Context) error {
    return s.rdb.Ping(ctx).Err()
}

func (s *RedisStorage) GetDomain(ctx context.Context) (*DomainConfig, error) {
    val, err := s.rdb.Get(ctx, domainConfigKey).Result()
    if errors.Is(err, redis.Nil) {
        return nil, ErrNotFound
    }
    if err != nil {
        return nil, fmt.Errorf("storage: get domain: %w", err)
    }

    var cfg DomainConfig
    if err := json.Unmarshal([]byte(val), &cfg); err != nil {
        return nil, fmt.Errorf("storage: unmarshal domain: %w", err)
    }
    return &cfg, nil
}

// UpdateDomain атомарно обновляет конфиг домена с оптимистичной блокировкой
//
// использует WATCH/MULTI/EXEC  читаем текущую версию  инкрементируем
// пишем в транзакции  если между WATCH и EXEC кто то успел изменить ключ
// Redis вернёт TxFailedErr  мы вернём ErrVersionConflict  caller повторяет
//
// это правильный выбор для данного случая  конфиг меняется редко
// только вручную администратором  конфликты практически исключены
// пессимистичные локи были бы излишеством
//
// Version начинается с 1 при первом создании и монотонно растёт

func (s *RedisStorage) UpdateDomain(ctx context.Context, cfg *DomainConfig) (*DomainConfig, error) {
    if cfg == nil {
        return nil, errors.New("storage: domain config must not be nil")
    }
    if cfg.PrimaryDomain == "" {
        return nil, errors.New("storage: primary_domain must not be empty")
    }
    if cfg.RedirectTarget == "" {
        return nil, errors.New("storage: redirect_target must not be empty")
    }

    var updated *DomainConfig

    err := s.rdb.Watch(ctx, func(tx *redis.Tx) error {
        current, err := getDomainTx(ctx, tx)
        if err != nil && !errors.Is(err, ErrNotFound) {
            return fmt.Errorf("storage: watch get: %w", err)
        }

        next := &DomainConfig{
            PrimaryDomain:  cfg.PrimaryDomain,
            RedirectTarget: cfg.RedirectTarget,
            Version:        1,
            UpdatedAt:      time.Now().UTC(),
        }
        if current != nil {
            next.Version = current.Version + 1
        }

        data, err := json.Marshal(next)
        if err != nil {
            return fmt.Errorf("storage: marshal domain: %w", err)
        }

        _, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
            pipe.Set(ctx, domainConfigKey, data, s.ttl)
            return nil
        })
        if err != nil {
            return err
        }

        updated = next
        return nil
    }, domainConfigKey)

    if errors.Is(err, redis.TxFailedErr) {
        return nil, ErrVersionConflict
    }
    if err != nil {
        return nil, fmt.Errorf("storage: update domain: %w", err)
    }

    return updated, nil
}

// getDomainTx внутренний хелпер для чтения внутри Watch транзакции
//
// вынесен отдельно чтобы не дублировать логику десериализации
// работает с *redis.Tx а не с *redis.Client  принципиально важно
// для корректной работы WATCH

func getDomainTx(ctx context.Context, tx *redis.Tx) (*DomainConfig, error) {
    val, err := tx.Get(ctx, domainConfigKey).Result()
    if errors.Is(err, redis.Nil) {
        return nil, ErrNotFound
    }
    if err != nil {
        return nil, fmt.Errorf("get: %w", err)
    }

    var cfg DomainConfig
    if err := json.Unmarshal([]byte(val), &cfg); err != nil {
        return nil, fmt.Errorf("unmarshal: %w", err)
    }
    return &cfg, nil
}