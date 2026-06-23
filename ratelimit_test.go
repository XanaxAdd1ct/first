package main

import (
    "context"
    "errors"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/stretchr/testify/assert"
    limiter "github.com/ulule/limiter/v3"
    "github.com/ulule/limiter/v3/drivers/store/memory"
)


func newBareServer() *Server {
    return &Server{}
}

func newTestLimiter(limit int64) *limiter.Limiter {
    rate := limiter.Rate{Period: time.Minute, Limit: limit}
    store := memory.NewStore()
    return limiter.New(store, rate)
}


type errorStore struct{}

func (e *errorStore) Get(ctx context.Context, key string, rate limiter.Rate) (limiter.Context, error) {
    return limiter.Context{}, errors.New("store error")
}
func (e *errorStore) Peek(ctx context.Context, key string, rate limiter.Rate) (limiter.Context, error) {
    return limiter.Context{}, errors.New("store error")
}
func (e *errorStore) Reset(ctx context.Context, key string, rate limiter.Rate) (limiter.Context, error) {
    return limiter.Context{}, errors.New("store error")
}
func (e *errorStore) Increment(ctx context.Context, key string, count int64, rate limiter.Rate) (limiter.Context, error) {
    return limiter.Context{}, errors.New("store error")
}

// --- Тесты ---


func TestCustomRateLimiter(t *testing.T) {
    gin.SetMode(gin.TestMode)

    srv := newTestServer(t, &mockStorage{
        domain: &DomainConfig{
            PrimaryDomain:  testDomain,
            RedirectTarget: testRedirect,
        },
    })

    called := false
    srv.WithRateLimiter(func(c *gin.Context) {
        called = true
        c.Next()
    })

    w := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodGet, "/health", nil)
    srv.ServeHTTP(w, req)

    assert.True(t, called, "кастомный rateLimiter должен был вызваться")
    assert.Equal(t, http.StatusOK, w.Code)
}
func TestRateLimit_NotReached_Passthrough(t *testing.T) {
    gin.SetMode(gin.TestMode)
    s := newBareServer()

    instance := newTestLimiter(100)

    w := httptest.NewRecorder()
    _, engine := gin.CreateTestContext(w)
    engine.Use(s.rateLimitWithInstance(instance))
    engine.GET("/test", func(c *gin.Context) {
        c.Status(http.StatusOK)
    })

    req := httptest.NewRequest(http.MethodGet, "/test", nil)
    engine.ServeHTTP(w, req)

    assert.Equal(t, http.StatusOK, w.Code)
}

func TestRateLimit_Reached_Returns429(t *testing.T) {
    gin.SetMode(gin.TestMode)
    s := newBareServer()

    // reachedStore не работает с limiter.New — тестируем middleware напрямую
    handler := s.rateLimitWithInstance(newTestLimiter(0))

    w := httptest.NewRecorder()
    _, engine := gin.CreateTestContext(w)
    engine.Use(handler)
    engine.GET("/test", func(c *gin.Context) {
        c.Status(http.StatusOK)
    })

    
    req := httptest.NewRequest(http.MethodGet, "/test", nil)
    engine.ServeHTTP(w, req)

    assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestRateLimit_StoreError_Passthrough(t *testing.T) {
    gin.SetMode(gin.TestMode)
    s := newBareServer()

    instance := limiter.New(&errorStore{}, limiter.Rate{
        Period: time.Minute,
        Limit:  100,
    })

    w := httptest.NewRecorder()
    _, engine := gin.CreateTestContext(w)
    engine.Use(s.rateLimitWithInstance(instance))
    engine.GET("/test", func(c *gin.Context) {
        c.Status(http.StatusOK)
    })

    req := httptest.NewRequest(http.MethodGet, "/test", nil)
    engine.ServeHTTP(w, req)

    assert.NotEqual(t, http.StatusTooManyRequests, w.Code)
}