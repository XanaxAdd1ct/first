package main

import (
    "context"
    "errors"
    "testing"
    "time"

    "github.com/alicebob/miniredis/v2"
)

func newTestStorage(t *testing.T) (*RedisStorage, *miniredis.Miniredis) {
    t.Helper()
    mr, err := miniredis.Run()
    if err != nil {
        t.Fatalf("miniredis: %v", err)
    }
    t.Cleanup(mr.Close)

    s, err := NewStorage("redis://"+mr.Addr(), 1*time.Hour)
    if err != nil {
        t.Fatalf("NewStorage: %v", err)
    }
    t.Cleanup(func() { _ = s.Close() })

    return s, mr
}

func validDomain() *DomainConfig {
    return &DomainConfig{
        PrimaryDomain:  "example.com",
        RedirectTarget: "https://redirect.example.com",
    }
}

func TestNew_InvalidURL(t *testing.T) {
    _, err := NewStorage("not-a-url", time.Hour)
    if err == nil {
        t.Fatal("expected error for invalid URL, got nil")
    }
}

func TestNew_EmptyURL(t *testing.T) {
    _, err := NewStorage("", time.Hour)
    if err == nil {
        t.Fatal("expected error for empty URL, got nil")
    }
}

func TestNew_ZeroTTL(t *testing.T) {
    _, err := NewStorage("redis://localhost:6379", 0)
    if err == nil {
        t.Fatal("expected error for zero TTL, got nil")
    }
}

func TestNew_UnreachableRedis(t *testing.T) {
    _, err := NewStorage("redis://localhost:1", time.Hour)
    if err == nil {
        t.Fatal("expected error for unreachable redis, got nil")
    }
}

func TestGetDomain_NotFound(t *testing.T) {
    s, _ := newTestStorage(t)

    _, err := s.GetDomain(context.Background())
    if !errors.Is(err, ErrNotFound) {
        t.Errorf("want ErrNotFound, got %v", err)
    }
}

func TestUpdateDomain_NilConfig(t *testing.T) {
    s, _ := newTestStorage(t)

    _, err := s.UpdateDomain(context.Background(), nil)
    if err == nil {
        t.Fatal("expected error for nil config, got nil")
    }
}

func TestUpdateDomain_EmptyPrimaryDomain(t *testing.T) {
    s, _ := newTestStorage(t)

    cfg := validDomain()
    cfg.PrimaryDomain = ""

    _, err := s.UpdateDomain(context.Background(), cfg)
    if err == nil {
        t.Fatal("expected error for empty primary_domain, got nil")
    }
}

func TestUpdateDomain_EmptyRedirectTarget(t *testing.T) {
    s, _ := newTestStorage(t)

    cfg := validDomain()
    cfg.RedirectTarget = ""

    _, err := s.UpdateDomain(context.Background(), cfg)
    if err == nil {
        t.Fatal("expected error for empty redirect_target, got nil")
    }
}

func TestUpdateDomain_FirstWrite(t *testing.T) {
    s, _ := newTestStorage(t)

    updated, err := s.UpdateDomain(context.Background(), validDomain())
    if err != nil {
        t.Fatalf("UpdateDomain: %v", err)
    }
    if updated.Version != 1 {
        t.Errorf("Version: want 1, got %d", updated.Version)
    }
    if updated.UpdatedAt.IsZero() {
        t.Error("UpdatedAt must not be zero")
    }
}

func TestUpdateDomain_VersionIncrement(t *testing.T) {
    s, _ := newTestStorage(t)
    ctx := context.Background()

    first, err := s.UpdateDomain(ctx, validDomain())
    if err != nil {
        t.Fatalf("first UpdateDomain: %v", err)
    }

    second, err := s.UpdateDomain(ctx, validDomain())
    if err != nil {
        t.Fatalf("second UpdateDomain: %v", err)
    }

    if second.Version != first.Version+1 {
        t.Errorf("Version: want %d, got %d", first.Version+1, second.Version)
    }
}

func TestGetDomain_AfterUpdate(t *testing.T) {
    s, _ := newTestStorage(t)
    ctx := context.Background()

    domain := validDomain()
    if _, err := s.UpdateDomain(ctx, domain); err != nil {
        t.Fatalf("UpdateDomain: %v", err)
    }

    got, err := s.GetDomain(ctx)
    if err != nil {
        t.Fatalf("GetDomain: %v", err)
    }
    if got.PrimaryDomain != domain.PrimaryDomain {
        t.Errorf("PrimaryDomain: want %q, got %q", domain.PrimaryDomain, got.PrimaryDomain)
    }
    if got.RedirectTarget != domain.RedirectTarget {
        t.Errorf("RedirectTarget: want %q, got %q", domain.RedirectTarget, got.RedirectTarget)
    }
    if got.Version != 1 {
        t.Errorf("Version: want 1, got %d", got.Version)
    }
}

func TestUpdateDomain_UpdatedAtIsRecent(t *testing.T) {
    s, _ := newTestStorage(t)

    before := time.Now().UTC().Add(-time.Second)
    updated, err := s.UpdateDomain(context.Background(), validDomain())
    if err != nil {
        t.Fatalf("UpdateDomain: %v", err)
    }
    after := time.Now().UTC().Add(time.Second)

    if updated.UpdatedAt.Before(before) || updated.UpdatedAt.After(after) {
        t.Errorf("UpdatedAt %v not in expected range [%v, %v]", updated.UpdatedAt, before, after)
    }
}

func TestGetDomain_TTLExpiry(t *testing.T) {
    s, mr := newTestStorage(t)
    ctx := context.Background()

    if _, err := s.UpdateDomain(ctx, validDomain()); err != nil {
        t.Fatalf("UpdateDomain: %v", err)
    }

    mr.FastForward(2 * time.Hour)

    _, err := s.GetDomain(ctx)
    if !errors.Is(err, ErrNotFound) {
        t.Errorf("after TTL expiry: want ErrNotFound, got %v", err)
    }
}

func TestUpdateDomain_VersionConflict(t *testing.T) {
    s, mr := newTestStorage(t)
    ctx := context.Background()

    if _, err := s.UpdateDomain(ctx, validDomain()); err != nil {
        t.Fatalf("setup UpdateDomain: %v", err)
    }

    mr.SetError("WATCH conflict")

    _, err := s.UpdateDomain(ctx, validDomain())
    if err == nil {
        t.Fatal("expected error on conflict, got nil")
    }
}

func TestClose(t *testing.T) {
    s, _ := newTestStorage(t)

    if err := s.Close(); err != nil {
        t.Errorf("Close: %v", err)
    }
}

func TestGetDomain_ContextCancelled(t *testing.T) {
    s, _ := newTestStorage(t)

    ctx, cancel := context.WithCancel(context.Background())
    cancel()

    _, err := s.GetDomain(ctx)
    if err == nil {
        t.Fatal("expected error for cancelled context, got nil")
    }
}

func TestUpdateDomain_ContextCancelled(t *testing.T) {
    s, _ := newTestStorage(t)

    ctx, cancel := context.WithCancel(context.Background())
    cancel()

    _, err := s.UpdateDomain(ctx, validDomain())
    if err == nil {
        t.Fatal("expected error for cancelled context, got nil")
    }
}
func TestPing_OK(t *testing.T) {
    s, _ := newTestStorage(t)
    if err := s.Ping(context.Background()); err != nil {
        t.Errorf("Ping: unexpected error: %v", err)
    }
}

func TestPing_AfterClose(t *testing.T) {
    s, _ := newTestStorage(t)
    _ = s.Close()
    if err := s.Ping(context.Background()); err == nil {
        t.Error("Ping: expected error after Close, got nil")
    }
}

func TestGetDomain_UnmarshalError(t *testing.T) {
    s, mr := newTestStorage(t)
    // Записываем невалидный JSON напрямую в miniredis
    mr.Set("domain_config", "not-valid-json")

    _, err := s.GetDomain(context.Background())
    if err == nil {
        t.Fatal("expected unmarshal error, got nil")
    }
}

func TestGetDomainTx_UnmarshalError(t *testing.T) {
    s, mr := newTestStorage(t)
    // Записываем невалидный JSON — getDomainTx вызывается внутри Watch
    mr.Set("domain_config", "not-valid-json")

    _, err := s.UpdateDomain(context.Background(), validDomain())
    if err == nil {
        t.Fatal("expected unmarshal error in getDomainTx, got nil")
    }
}

func TestUpdateDomain_TxPipelineError(t *testing.T) {
    s, mr := newTestStorage(t)
    ctx := context.Background()

    // Первый write успешен
    if _, err := s.UpdateDomain(ctx, validDomain()); err != nil {
        t.Fatalf("setup: %v", err)
    }

    // Имитируем ошибку redis.TxFailedErr через SetError после Watch
    mr.SetError("EXECABORT Transaction discarded")

    _, err := s.UpdateDomain(ctx, validDomain())
    if err == nil {
        t.Fatal("expected tx error, got nil")
    }
}

func TestUpdateDomain_WatchGetError(t *testing.T) {
    s, mr := newTestStorage(t)
    // Записываем невалидный JSON — Watch внутри вызовет getDomainTx -> unmarshal error
    mr.Set("domain_config", "{invalid}")
    _, err := s.UpdateDomain(context.Background(), validDomain())
    if err == nil {
        t.Fatal("expected watch get error, got nil")
    }
}

func TestUpdateDomain_TxPipelinedError(t *testing.T) {
    s, mr := newTestStorage(t)
    ctx := context.Background()
    // Первый write успешен
    if _, err := s.UpdateDomain(ctx, validDomain()); err != nil {
        t.Fatalf("setup: %v", err)
    }
    // Сбрасываем ошибку, затем ставим её перед вторым вызовом
    mr.SetError("")
    mr.SetError("ERR something went wrong")
    _, err := s.UpdateDomain(ctx, validDomain())
    if err == nil {
        t.Fatal("expected pipeline error, got nil")
    }
}

func TestGetDomainTx_GetError(t *testing.T) {
    s, mr := newTestStorage(t)
    ctx := context.Background()

    // Сначала пишем валидные данные
    if _, err := s.UpdateDomain(ctx, validDomain()); err != nil {
        t.Fatalf("setup: %v", err)
    }

    // Сбрасываем ошибку и ставим новую — именно для GET внутри транзакции
    mr.SetError("")
    mr.SetError("ERR connection refused")

    _, err := s.UpdateDomain(ctx, validDomain())
    if err == nil {
        t.Fatal("expected error from getDomainTx Get, got nil")
    }
}

func TestUpdateDomain_TxPipelineInternalError(t *testing.T) {
    s, mr := newTestStorage(t)
    ctx := context.Background()

    // Первый write успешен
    if _, err := s.UpdateDomain(ctx, validDomain()); err != nil {
        t.Fatalf("setup: %v", err)
    }

    // Убираем ошибку, затем ставим ошибку на TxPipelined
    mr.SetError("")

    // Ломаем SET внутри TxPipelined
    mr.SetError("EXECABORT Transaction discarded because of errors during execution")

    _, err := s.UpdateDomain(ctx, validDomain())
    if err == nil {
        t.Fatal("expected TxPipelined error, got nil")
    }
}