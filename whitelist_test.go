package main

import (
    "io"
    "log/slog"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/gin-gonic/gin"
    "github.com/stretchr/testify/assert"
)

func newTestWhitelist(entries []string) *IPWhitelist {
    return NewIPWhitelist(entries,
        slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestNewIPWhitelist_Empty(t *testing.T) {
    wl := newTestWhitelist([]string{})
    assert.Empty(t, wl.entries)
}

func TestNewIPWhitelist_SingleIP(t *testing.T) {
    wl := newTestWhitelist([]string{"192.168.1.1"})
    assert.Len(t, wl.entries, 1)
}

func TestNewIPWhitelist_CIDR(t *testing.T) {
    wl := newTestWhitelist([]string{"192.168.1.0/24"})
    assert.Len(t, wl.entries, 1)
    assert.NotNil(t, wl.entries[0].cidr)
}

func TestNewIPWhitelist_InvalidEntry_Skipped(t *testing.T) {
    wl := newTestWhitelist([]string{"not-an-ip", "192.168.1.1"})
    assert.Len(t, wl.entries, 1)
}

func TestNewIPWhitelist_EmptyString_Skipped(t *testing.T) {
    wl := newTestWhitelist([]string{"", "192.168.1.1"})
    assert.Len(t, wl.entries, 1)
}

func TestIPWhitelist_Empty_AllowsAll(t *testing.T) {
    wl := newTestWhitelist([]string{})
    assert.True(t, wl.allowed(parseTestIP("1.2.3.4")))
    assert.True(t, wl.allowed(parseTestIP("192.168.1.1")))
}

func TestIPWhitelist_AllowsListedIP(t *testing.T) {
    wl := newTestWhitelist([]string{"1.2.3.4"})
    assert.True(t, wl.allowed(parseTestIP("1.2.3.4")))
}

func TestIPWhitelist_BlocksUnlistedIP(t *testing.T) {
    wl := newTestWhitelist([]string{"1.2.3.4"})
    assert.False(t, wl.allowed(parseTestIP("5.6.7.8")))
}

func TestIPWhitelist_AllowsCIDRRange(t *testing.T) {
    wl := newTestWhitelist([]string{"192.168.1.0/24"})
    assert.True(t, wl.allowed(parseTestIP("192.168.1.1")))
    assert.True(t, wl.allowed(parseTestIP("192.168.1.254")))
}

func TestIPWhitelist_BlocksOutsideCIDR(t *testing.T) {
    wl := newTestWhitelist([]string{"192.168.1.0/24"})
    assert.False(t, wl.allowed(parseTestIP("192.168.2.1")))
}

func TestIPWhitelist_Localhost(t *testing.T) {
    wl := newTestWhitelist([]string{"127.0.0.1"})
    assert.True(t, wl.allowed(parseTestIP("127.0.0.1")))
    assert.False(t, wl.allowed(parseTestIP("127.0.0.2")))
}

func TestIPWhitelistMiddleware_EmptyAllowsAll(t *testing.T) {
    gin.SetMode(gin.TestMode)
    wl := newTestWhitelist([]string{})

    w := httptest.NewRecorder()
    _, engine := gin.CreateTestContext(w)
    engine.Use(wl.Middleware())
    engine.GET("/test", func(c *gin.Context) {
        c.Status(http.StatusOK)
    })

    req := httptest.NewRequest(http.MethodGet, "/test", nil)
    engine.ServeHTTP(w, req)
    assert.Equal(t, http.StatusOK, w.Code)
}

func TestIPWhitelistMiddleware_BlocksUnknownIP(t *testing.T) {
    gin.SetMode(gin.TestMode)
    wl := newTestWhitelist([]string{"1.2.3.4"})

    w := httptest.NewRecorder()
    _, engine := gin.CreateTestContext(w)
    engine.Use(wl.Middleware())
    engine.GET("/test", func(c *gin.Context) {
        c.Status(http.StatusOK)
    })

    req := httptest.NewRequest(http.MethodGet, "/test", nil)
    req.RemoteAddr = "5.6.7.8:9999"
    engine.ServeHTTP(w, req)
    assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestIPWhitelistMiddleware_AllowsListedIP(t *testing.T) {
    gin.SetMode(gin.TestMode)
    wl := newTestWhitelist([]string{"192.0.2.1"})

    w := httptest.NewRecorder()
    _, engine := gin.CreateTestContext(w)
    engine.Use(wl.Middleware())
    engine.GET("/test", func(c *gin.Context) {
        c.Status(http.StatusOK)
    })

    req := httptest.NewRequest(http.MethodGet, "/test", nil)
    req.RemoteAddr = "192.0.2.1:9999"
    engine.ServeHTTP(w, req)
    assert.Equal(t, http.StatusOK, w.Code)
}

func parseTestIP(s string) net.IP {
    return net.ParseIP(s)
}
