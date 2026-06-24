package main

import (
    "context"
    "crypto/subtle"
    "errors"
    "log/slog"
    "net/http"
    "net/url"
    "strings"
    "sync"
    "time"

    "github.com/gin-contrib/cors"
    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    limiter "github.com/ulule/limiter/v3"
    "github.com/ulule/limiter/v3/drivers/store/memory"
)

const (
    rateLimitPeriod = time.Minute
    rateLimitCount  = 100
    healthTimeout   = 2 * time.Second
    handlerTimeout  = 10 * time.Second
    minTokenLen     = 32
    maxBodyBytes    = 1 << 20
    nonceHeader     = "X-Nonce"
    nonceMaxStore   = 100000
    nonceTTL        = 5 * time.Minute
    cleanupTick     = 1 * time.Minute
)

type Server struct {
    cfg             *APIConfig
    store           Storage
    keyRing         KeyRinger
    log             *slog.Logger
    metrics         *serverMetrics
    router          *gin.Engine
    rateLimiter     gin.HandlerFunc
    securityMonitor *SecurityMonitor
    nonces          *nonceStore
}

func New(
    cfg *APIConfig,
    store Storage,
    keyRing KeyRinger,
    nonces *nonceStore,
    log *slog.Logger,
    reg prometheus.Registerer,
    secCfg SecurityConfig,
) (*Server, error) {
    if cfg == nil || store == nil || keyRing == nil || log == nil || nonces == nil {
        return nil, errors.New("api: dependencies must not be nil")
    }
    if len(cfg.AdminToken) < minTokenLen {
        return nil, errors.New("api: admin token too short")
    }

    m, err := newServerMetrics(reg)
    if err != nil {
        return nil, err
    }

    s := &Server{
        cfg:             cfg,
        store:           store,
        keyRing:         keyRing,
        log:             log,
        metrics:         m,
        securityMonitor: NewSecurityMonitor(log, secCfg),
        nonces:          nonces,
    }
    s.router = s.buildRouter()
    return s, nil
}

func (s *Server) Close() {
    s.nonces.shutdown()
    s.securityMonitor.Shutdown()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    s.router.ServeHTTP(w, r)
}

func (s *Server) buildRouter() *gin.Engine {
    gin.SetMode(gin.ReleaseMode)
    r := gin.New()
    r.Use(gin.Recovery())
    r.Use(s.structuredLogger())
    r.Use(cors.Default())
    r.Use(s.bodyLimit())
    r.Use(SecurityMiddleware(s.securityMonitor))

    rate := limiter.Rate{Period: rateLimitPeriod, Limit: rateLimitCount}
    store := memory.NewStore()
    r.Use(s.rateLimitWithInstance(limiter.New(store, rate)))

    r.GET("/metrics", gin.WrapH(promhttp.Handler()))
    r.GET("/health", s.handleHealth)

    agent := r.Group("/api/v1/agent")
    {
        agent.POST("/checkin", s.handleAgentCheckin)
    }

    wl := NewIPWhitelist(s.cfg.AdminAllowedIPs, s.log)
    admin := r.Group("/api/v1/admin")
    {
        admin.Use(wl.Middleware())
        admin.Use(s.bearerAuth())
        admin.Use(nonceMiddleware(s.nonces))
        admin.POST("/update_domain", s.handleAdminUpdateDomain)
        admin.POST("/rotate_key", s.handleAdminRotateKey)
    }

    return r
}

func (s *Server) structuredLogger() gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        c.Next()
        s.log.Info("request",
            slog.String("method", c.Request.Method),
            slog.String("path", c.Request.URL.Path),
            slog.Int("status", c.Writer.Status()),
            slog.Duration("duration", time.Since(start)),
            slog.String("ip", c.ClientIP()),
        )
    }
}

func (s *Server) bodyLimit() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)
        c.Next()
    }
}

func (s *Server) rateLimitWithInstance(instance *limiter.Limiter) gin.HandlerFunc {
    return func(c *gin.Context) {
        ctx, err := instance.Get(c.Request.Context(), c.ClientIP())
        if err != nil {
            c.Next()
            return
        }
        if ctx.Reached {
            c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
            return
        }
        c.Next()
    }
}

func (s *Server) bearerAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        header := c.GetHeader("Authorization")
        token, ok := strings.CutPrefix(header, "Bearer ")
        if !ok || token == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
            return
        }
        if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.AdminToken)) != 1 {
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid token"})
            return
        }
        c.Next()
    }
}

func (s *Server) handleHealth(c *gin.Context) {
    ctx, cancel := context.WithTimeout(c.Request.Context(), healthTimeout)
    defer cancel()
    if err := s.store.Ping(ctx); err != nil {
        c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleAgentCheckin(c *gin.Context) {
    agentID := c.Query("agent_id")
    if agentID == "" {
        agentID = uuid.New().String()
    }
    ctx, cancel := context.WithTimeout(c.Request.Context(), handlerTimeout)
    defer cancel()

    domain, err := s.store.GetDomain(ctx)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "storage error"})
        return
    }

    payload := newDomainPayload(domain)
    sig, keyID, _ := s.keyRing.Sign(payload.toMap())

    c.JSON(http.StatusOK, gin.H{
        "action":      "update_domain",
        "payload":     payload,
        "signature":   sig,
        "key_version": keyID,
        "agent_id":    agentID,
    })
}

func (s *Server) handleAdminUpdateDomain(c *gin.Context) {
    var req struct {
        PrimaryDomain  string `json:"primary_domain" binding:"required"`
        RedirectTarget string `json:"redirect_target" binding:"required"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    ctx, cancel := context.WithTimeout(c.Request.Context(), handlerTimeout)
    defer cancel()

    updated, err := s.store.UpdateDomain(ctx, &DomainConfig{
        PrimaryDomain:  req.PrimaryDomain,
        RedirectTarget: req.RedirectTarget,
    })
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "storage error"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"status": "ok", "version": updated.Version})
}

func (s *Server) handleAdminRotateKey(c *gin.Context) {
    var req struct {
        NewSecret string `json:"new_secret" binding:"required"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    if err := s.keyRing.Rotate(req.NewSecret); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "rotation failed"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) createDefaultDomain(ctx context.Context) (*DomainConfig, error) {
    return s.store.UpdateDomain(ctx, &DomainConfig{
        PrimaryDomain:  s.cfg.DefaultDomain,
        RedirectTarget: s.cfg.DefaultRedirect,
    })
}

func newDomainPayload(d *DomainConfig) DomainPayload {
    return DomainPayload{
        PrimaryDomain:  d.PrimaryDomain,
        RedirectTarget: d.RedirectTarget,
        Version:        d.Version,
        UpdatedAt:      d.UpdatedAt,
    }
}

type nonceStore struct {
    mu     sync.RWMutex
    data   map[string]time.Time
    ctx    context.Context
    cancel context.CancelFunc
}

func newNonceStore() *nonceStore {
    ctx, cancel := context.WithCancel(context.Background())
    ns := &nonceStore{
        data:   make(map[string]time.Time),
        ctx:    ctx,
        cancel: cancel,
    }
    go ns.cleanup()
    return ns
}

func (ns *nonceStore) shutdown() { ns.cancel() }

func (ns *nonceStore) cleanup() {
    ticker := time.NewTicker(cleanupTick)
    defer ticker.Stop()
    for {
        select {
        case <-ns.ctx.Done():
            return
        case <-ticker.C:
            now := time.Now()
            ns.mu.Lock()
            for n, ts := range ns.data {
                if now.Sub(ts) > nonceTTL {
                    delete(ns.data, n)
                }
            }
            ns.mu.Unlock()
        }
    }
}

func nonceMiddleware(ns *nonceStore) gin.HandlerFunc {
    return func(c *gin.Context) {
        nonce := c.GetHeader(nonceHeader)
        if len(nonce) != 32 {
            c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid nonce"})
            return
        }
        ns.mu.Lock()
        defer ns.mu.Unlock()
        if _, exists := ns.data[nonce]; exists {
            c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "nonce used"})
            return
        }
        ns.data[nonce] = time.Now()
        c.Next()
    }
}
