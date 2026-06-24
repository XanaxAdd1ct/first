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

type KeyRinger interface {
    Sign(payload map[string]interface{}) (signature string, keyID int, err error)
    Verify(payload map[string]interface{}, signature string, keyID int) error
    Rotate(newSecret string) error
    CurrentID() int
}

type APIConfig struct {
    AdminToken      string
    DefaultDomain   string
    DefaultRedirect string
    AdminAllowedIPs []string
}

type DomainPayload struct {
    PrimaryDomain  string    `json:"primary_domain"`
    RedirectTarget string    `json:"redirect_target"`
    Version        int64     `json:"version"`
    UpdatedAt      time.Time `json:"updated_at"`
}

func (p DomainPayload) toMap() map[string]interface{} {
    return map[string]interface{}{
        "primary_domain":  p.PrimaryDomain,
        "redirect_target": p.RedirectTarget,
        "version":         p.Version,
        "updated_at":      p.UpdatedAt,
    }
}

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
        securityMonitor: NewSecurityMonitor(log, SecurityConfig{}),
        nonces:          nonces,
    }
    s.router = s.buildRouter()
    return s, nil
}

func (s *Server) WithRateLimiter(h gin.HandlerFunc) {
    s.rateLimiter = h
    s.router = s.buildRouter()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    s.router.ServeHTTP(w, r)
}

func (s *Server) buildRouter() *gin.Engine {
    r := gin.New()
    r.Use(gin.Recovery())
    r.Use(s.structuredLogger())
    r.Use(cors.Default())
    r.Use(s.bodyLimit())
    r.Use(SecurityMiddleware(s.securityMonitor))

    if s.rateLimiter != nil {
        r.Use(s.rateLimiter)
    } else {
        rate := limiter.Rate{Period: rateLimitPeriod, Limit: rateLimitCount}
        store := memory.NewStore()
        r.Use(s.rateLimitWithInstance(limiter.New(store, rate)))
    }

    r.GET("/metrics", gin.WrapH(promhttp.Handler()))
    r.GET("/health", s.handleHealth)

    agent := r.Group("/api/v1/agent")
    agent.POST("/checkin", s.handleAgentCheckin)

    wl := NewIPWhitelist(s.cfg.AdminAllowedIPs, s.log)

    admin := r.Group("/api/v1/admin")
    admin.Use(wl.Middleware())
    admin.Use(s.bearerAuth())
    admin.Use(nonceMiddleware(s.nonces))
    admin.POST("/update_domain", s.handleAdminUpdateDomain)
    admin.POST("/rotate_key", s.handleAdminRotateKey)

    return r
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
            c.AbortWithStatusJSON(http.StatusTooManyRequests, errorResponse("rate limit exceeded"))
            return
        }
        c.Next()
    }
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

func (s *Server) bearerAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        header := c.GetHeader("Authorization")
        token, ok := strings.CutPrefix(header, "Bearer ")
        if !ok || token == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse("missing Bearer token"))
            return
        }
        if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.AdminToken)) != 1 {
            c.AbortWithStatusJSON(http.StatusForbidden, errorResponse("invalid token"))
            return
        }
        c.Next()
    }
}

func (s *Server) handleHealth(c *gin.Context) {
    ctx, cancel := context.WithTimeout(c.Request.Context(), healthTimeout)
    defer cancel()

    if err := s.store.Ping(ctx); err != nil {
        s.log.Warn("health check: redis unavailable", slog.String("err", err.Error()))
        c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy", "error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleAgentCheckin(c *gin.Context) {
    const endpoint = "checkin"
    s.metrics.requestsTotal.WithLabelValues(endpoint).Inc()

    agentID := c.Query("agent_id")
    if agentID == "" {
        agentID = uuid.New().String()
    }

    ctx, cancel := context.WithTimeout(c.Request.Context(), handlerTimeout)
    defer cancel()

    domain, err := s.store.GetDomain(ctx)
    if errors.Is(err, ErrNotFound) {
        domain, err = s.createDefaultDomain(ctx)
    }
    if err != nil {
        s.log.Error("checkin: get domain failed", slog.String("err", err.Error()))
        s.metrics.errorsTotal.WithLabelValues(endpoint, "500").Inc()
        c.JSON(http.StatusInternalServerError, errorResponse("storage error"))
        return
    }

    payload := newDomainPayload(domain)
    sig, keyID, err := s.keyRing.Sign(payload.toMap())
    if err != nil {
        s.log.Error("checkin: sign failed", slog.String("err", err.Error()))
        s.metrics.errorsTotal.WithLabelValues(endpoint, "500").Inc()
        c.JSON(http.StatusInternalServerError, errorResponse("signing error"))
        return
    }

    s.metrics.domainVersion.WithLabelValues(domain.PrimaryDomain).Set(float64(domain.Version))

    c.JSON(http.StatusOK, gin.H{
        "action":      "update_domain",
        "payload":     payload,
        "signature":   sig,
        "key_version": keyID,
        "agent_id":    agentID,
    })
}

type updateDomainRequest struct {
    PrimaryDomain  string `json:"primary_domain"  binding:"required"`
    RedirectTarget string `json:"redirect_target" binding:"required"`
}

func (s *Server) handleAdminUpdateDomain(c *gin.Context) {
    const endpoint = "update_domain"
    s.metrics.requestsTotal.WithLabelValues(endpoint).Inc()

    var req updateDomainRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, errorResponse(err.Error()))
        return
    }
    if err := validateDomain(req.PrimaryDomain); err != nil {
        c.JSON(http.StatusBadRequest, errorResponse(err.Error()))
        return
    }
    if err := validateRedirectURL(req.RedirectTarget); err != nil {
        c.JSON(http.StatusBadRequest, errorResponse(err.Error()))
        return
    }

    ctx, cancel := context.WithTimeout(c.Request.Context(), handlerTimeout)
    defer cancel()

    updated, err := s.store.UpdateDomain(ctx, &DomainConfig{
        PrimaryDomain:  req.PrimaryDomain,
        RedirectTarget: req.RedirectTarget,
    })
    if err != nil {
        s.log.Error("admin: update domain failed", slog.String("err", err.Error()))
        s.metrics.errorsTotal.WithLabelValues(endpoint, "500").Inc()
        c.JSON(http.StatusInternalServerError, errorResponse("storage error"))
        return
    }

    s.log.Info("domain updated by admin", slog.String("domain", updated.PrimaryDomain), slog.Int64("version", updated.Version))
    c.JSON(http.StatusOK, gin.H{"status": "ok", "version": updated.Version})
}

func (s *Server) handleAdminRotateKey(c *gin.Context) {
    var req struct {
        NewSecret string `json:"new_secret" binding:"required"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, errorResponse(err.Error()))
        return
    }
    if len(req.NewSecret) < minTokenLen {
        c.JSON(http.StatusBadRequest, errorResponse("new_secret too short"))
        return
    }
    if err := s.keyRing.Rotate(req.NewSecret); err != nil {
        s.log.Error("admin: rotate key failed", slog.String("err", err.Error()))
        c.JSON(http.StatusInternalServerError, errorResponse("key rotation failed"))
        return
    }

    s.log.Info("HMAC key rotated", slog.Int("key_id", s.keyRing.CurrentID()))
    c.JSON(http.StatusOK, gin.H{"status": "ok", "key_id": s.keyRing.CurrentID()})
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

func validateDomain(domain string) error {
    if domain == "" {
        return errors.New("primary_domain must not be empty")
    }
    check := strings.TrimPrefix(domain, "*.")
    if check == "" {
        return errors.New("primary_domain: invalid format")
    }
    if strings.ContainsAny(check, " \t\n/\\@#?") {
        return errors.New("primary_domain: invalid characters")
    }
    parts := strings.Split(check, ".")
    if len(parts) < 2 {
        return errors.New("primary_domain: must contain at least one dot")
    }
    for _, part := range parts {
        if part == "" || len(part) > 63 || !isValidLabel(part) {
            return errors.New("primary_domain: invalid label")
        }
    }
    return nil
}

func isValidLabel(s string) bool {
    for _, r := range s {
        if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
            return false
        }
    }
    return s[0] != '-' && s[len(s)-1] != '-'
}

func validateRedirectURL(raw string) error {
    if raw == "" {
        return errors.New("redirect_target must not be empty")
    }
    u, err := url.ParseRequestURI(raw)
    if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
        return errors.New("redirect_target: invalid URL")
    }
    return nil
}

func errorResponse(msg string) gin.H {
    return gin.H{"error": msg}
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

func (ns *nonceStore) shutdown() {
    ns.cancel()
}

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
            for nonce, ts := range ns.data {
                if now.Sub(ts) > nonceTTL {
                    delete(ns.data, nonce)
                }
            }
            ns.mu.Unlock()
        }
    }
}

func isValidNonceFormat(nonce string) bool {
    if len(nonce) != 32 {
        return false
    }
    for _, r := range nonce {
        if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
            return false
        }
    }
    return true
}

func nonceMiddleware(ns *nonceStore) gin.HandlerFunc {
    return func(c *gin.Context) {
        nonce := c.GetHeader(nonceHeader)
        if !isValidNonceFormat(nonce) {
            c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid or missing X-Nonce"})
            return
        }

        ns.mu.RLock()
        _, exists := ns.data[nonce]
        ns.mu.RUnlock()

        if exists {
            c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "nonce already used"})
            return
        }

        ns.mu.Lock()
        if len(ns.data) >= nonceMaxStore {
            ns.mu.Unlock()
            c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "nonce storage full"})
            return
        }

        if _, exists := ns.data[nonce]; exists {
            ns.mu.Unlock()
            c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "nonce already used"})
            return
        }

        ns.data[nonce] = time.Now()
        ns.mu.Unlock()
        c.Next()
    }
}
