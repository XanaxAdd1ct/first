// точка входа для http сервера  здесь собирается роутер  middleware и все хендлеры
// сервер намеренно не знает ничего про конфиг и redis напрямую
// всё приходит через интерфейсы  это позволяет подменять зависимости в тестах
package main

import (
    "context"
    "errors"
    "log/slog"
    "net/http"
    "net/url"
    "strings"
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
)

// KeyRinger интерфейс для подписи и верификации payload-ов
// вынесен в интерфейс чтобы в тестах можно было подменить на mock
// и проверить поведение хендлеров при ошибках подписи
type KeyRinger interface {
    Sign(payload map[string]interface{}) (signature string, keyID int, err error)
    Verify(payload map[string]interface{}, signature string, keyID int) error
    Rotate(newSecret string) error
    CurrentID() int
}

// APIConfig минимальный конфиг который нужен серверу
// намеренно отделён от общего Config  хендлерам не нужно знать
// про redis url или log level  только то что реально используется
type APIConfig struct {
    AdminToken      string
    DefaultDomain   string
    DefaultRedirect string
}

// DomainPayload данные которые сервер отдаёт агенту при checkin
// это то что подписывается hmac  поэтому структура фиксированная
type DomainPayload struct {
    PrimaryDomain  string    `json:"primary_domain"`
    RedirectTarget string    `json:"redirect_target"`
    Version        int64     `json:"version"`
    UpdatedAt      time.Time `json:"updated_at"`
}
// toMap конвертирует payload в map для передачи в KeyRinger.Sign()
// нужно потому что Sign принимает map а не структуру
// это позволяет подписывать любые данные  не только DomainPayload
func (p DomainPayload) toMap() map[string]interface{} {
    return map[string]interface{}{
        "primary_domain":  p.PrimaryDomain,
        "redirect_target": p.RedirectTarget,
        "version":         p.Version,
        "updated_at":      p.UpdatedAt,
    }
}
// Server основная структура сервиса  хранит все зависимости
// router пересобирается при вызове WithRateLimiter
// rateLimiter nil по умолчанию  в этом случае используется встроенный
type Server struct {
    cfg         *APIConfig
    store       Storage
    keyRing     KeyRinger
    log         *slog.Logger
    metrics     *serverMetrics
    router      *gin.Engine
    rateLimiter gin.HandlerFunc 
}


// New создаёт сервер и проверяет все зависимости
// падает сразу если что то nil или токен слишком короткий
// лучше упасть здесь чем получить панику во время запроса
func New(
    cfg *APIConfig,
    store Storage,
    keyRing KeyRinger,
    log *slog.Logger,
    reg prometheus.Registerer,
) (*Server, error) {
    if cfg == nil {
        return nil, errors.New("api: config must not be nil")
    }
    if store == nil {
        return nil, errors.New("api: storage must not be nil")
    }
    if keyRing == nil {
        return nil, errors.New("api: keyring must not be nil")
    }
    if log == nil {
        return nil, errors.New("api: logger must not be nil")
    }
    if len(cfg.AdminToken) < minTokenLen {
        return nil, errors.New("api: admin token too short")
    }

    m, err := newServerMetrics(reg)
    if err != nil {
        return nil, err
    }

    s := &Server{
        cfg:     cfg,
        store:   store,
        keyRing: keyRing,
        log:     log,
        metrics: m,
    }
    s.router = s.buildRouter()
    return s, nil
}

// WithRateLimiter подменяет встроенный rate limiter на внешний
// используется в тестах чтобы покрыть ветку if s.rateLimiter != nil
// в production не используется

func (s *Server) WithRateLimiter(h gin.HandlerFunc) {
    s.rateLimiter = h
    s.router = s.buildRouter()
}

// ServeHTTP реализует интерфейс http.Handler
// позволяет передавать Server напрямую в http.Server без обёрток
// так же используется в тестах через httptest.NewRecorder()
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    s.router.ServeHTTP(w, r)
}
// buildRouter собирает все маршруты и middleware
// порядок middleware важен  recovery должен быть первым
// rateLimiter после cors  чтобы preflight запросы не считались в лимите
func (s *Server) buildRouter() *gin.Engine {
    r := gin.New()
    r.Use(gin.Recovery())
    r.Use(s.structuredLogger())
    r.Use(cors.Default())

    if s.rateLimiter != nil {
        r.Use(s.rateLimiter)
    } else {
        rate  := limiter.Rate{Period: rateLimitPeriod, Limit: rateLimitCount}
        store := memory.NewStore()
        r.Use(s.rateLimitWithInstance(limiter.New(store, rate)))
    }

    r.GET("/metrics", gin.WrapH(promhttp.Handler()))
    r.GET("/health", s.handleHealth)

    agent := r.Group("/api/v1/agent")
    agent.POST("/checkin", s.handleAgentCheckin)

    admin := r.Group("/api/v1/admin")
    admin.Use(s.bearerAuth())
    admin.POST("/update_domain", s.handleAdminUpdateDomain)
    admin.POST("/rotate_key", s.handleAdminRotateKey)

    return r
}
// rateLimitWithInstance middleware для ограничения запросов по ip
// если хранилище лимитера недоступно  пропускаем запрос
// лучше пропустить лишний запрос чем блокировать всех из за ошибки
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
// structuredLogger пишет каждый запрос в лог после его завершения
// время замеряется до c.Next()  чтобы включить всё время обработки
func (s *Server) structuredLogger() gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        c.Next()
        s.log.Info("request",
            slog.String("method",     c.Request.Method),
            slog.String("path",       c.Request.URL.Path),
            slog.Int("status",        c.Writer.Status()),
            slog.Duration("duration", time.Since(start)),
            slog.String("ip",         c.ClientIP()),
        )
    }
}
// bearerAuth проверяет токен из заголовка Authorization
// 401 если заголовок отсутствует  403 если токен неверный
// разделение намеренное  401 означает не аутентифицирован  403 означает нет доступа
func (s *Server) bearerAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        header := c.GetHeader("Authorization")
        token, ok := strings.CutPrefix(header, "Bearer ")
        if !ok || token == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, errorResponse("missing Bearer token"))
            return
        }
        if token != s.cfg.AdminToken {
            c.AbortWithStatusJSON(http.StatusForbidden, errorResponse("invalid token"))
            return
        }
        c.Next()
    }
}
// withTimeout создаёт контекст с таймаутом из контекста gin запроса
// вынесен в хелпер чтобы не повторять одну и ту же строку в каждом хендлере
// cancel нужно вызывать через defer сразу после вызова этой функции
func withTimeout(c *gin.Context, d time.Duration) (context.Context, context.CancelFunc) {
    return context.WithTimeout(c.Request.Context(), d)
}
// handleHealth проверяет доступность redis
// используется как liveness probe в kubernetes
// если redis недоступен  возвращает 503 чтобы балансировщик убрал инстанс
func (s *Server) handleHealth(c *gin.Context) {
    ctx, cancel := withTimeout(c, healthTimeout)
    defer cancel()

    if err := s.store.Ping(ctx); err != nil {
        s.log.Warn("health check: redis unavailable",
            slog.String("err", err.Error()),
        )
        c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy", "error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
// handleAgentCheckin основной эндпоинт  агент получает подписанный конфиг
// если конфига в redis нет  создаёт дефолтный из конфига сервера
// agent_id необязательный  если не передан  генерируется uuid
func (s *Server) handleAgentCheckin(c *gin.Context) {
    const endpoint = "checkin"
    s.metrics.requestsTotal.WithLabelValues(endpoint).Inc()

    agentID := c.Query("agent_id")
    if agentID == "" {
        agentID = uuid.New().String()
    }

    ctx, cancel := withTimeout(c, handlerTimeout)
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
// handleAdminUpdateDomain обновляет домен и редирект
// валидирует домен по rfc  схему редиректа  пустые поля
// возвращает новую версию конфига  агенты узнают об изменении на следующем checkin
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

    ctx, cancel := withTimeout(c, handlerTimeout)
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

    s.log.Info("domain updated by admin",
        slog.String("domain",  updated.PrimaryDomain),
        slog.Int64("version",  updated.Version),
    )
    c.JSON(http.StatusOK, gin.H{"status": "ok", "version": updated.Version})
}

type rotateKeyRequest struct {
    NewSecret string `json:"new_secret" binding:"required"`
}
// handleAdminRotateKey заменяет текущий hmac ключ новым
// старый ключ остаётся валидным ещё 1 час  см crypto.go
// минимальная длина нового секрета 32 символа  проверяется здесь и в keyring
func (s *Server) handleAdminRotateKey(c *gin.Context) {
    var req rotateKeyRequest
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
// createDefaultDomain создаёт первоначальный конфиг при старте сервиса
// вызывается только когда в redis ещё нет записи  то есть первый запуск
// значения берутся из конфига сервера  DEFAULT_DOMAIN и DEFAULT_REDIRECT
func (s *Server) createDefaultDomain(ctx context.Context) (*DomainConfig, error) {
    return s.store.UpdateDomain(ctx, &DomainConfig{
        PrimaryDomain:  s.cfg.DefaultDomain,
        RedirectTarget: s.cfg.DefaultRedirect,
    })
}
// newDomainPayload конвертирует DomainConfig из storage в DomainPayload для ответа
// разделение намеренное  DomainConfig это внутренняя структура хранилища
// DomainPayload это то что уходит агенту по сети  менять одно не должно ломать другое
func newDomainPayload(d *DomainConfig) DomainPayload {
    return DomainPayload{
        PrimaryDomain:  d.PrimaryDomain,
        RedirectTarget: d.RedirectTarget,
        Version:        d.Version,
        UpdatedAt:      d.UpdatedAt,
    }
}
// validateDomain проверяет доменное имя по правилам rfc 1035
// поддерживает wildcard домены вида *.example.com
// каждый лейбл проверяется отдельно  длина  символы  дефисы по краям
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
        if part == "" {
            return errors.New("primary_domain: empty label")
        }
        if len(part) > 63 {
            return errors.New("primary_domain: label too long (max 63)")
        }
        if !isValidLabel(part) {
            return errors.New("primary_domain: invalid characters in label")
        }
    }
    return nil
}
// isValidLabel проверяет один сегмент доменного имени
// допустимы только буквы  цифры и дефис
// дефис не может быть первым или последним символом
func isValidLabel(s string) bool {
    for _, r := range s {
        if !((r >= 'a' && r <= 'z') ||
            (r >= 'A' && r <= 'Z') ||
            (r >= '0' && r <= '9') ||
            r == '-') {
            return false
        }
    }
    return s[0] != '-' && s[len(s)-1] != '-'
}
// validateRedirectURL проверяет что редирект это валидный http или https url
// ftp  mailto и прочие схемы не принимаются
func validateRedirectURL(raw string) error {
    if raw == "" {
        return errors.New("redirect_target must not be empty")
    }
    u, err := url.ParseRequestURI(raw)
    if err != nil {
        return errors.New("redirect_target: invalid URL")
    }
    if u.Scheme != "http" && u.Scheme != "https" {
        return errors.New("redirect_target: scheme must be http or https")
    }
    if u.Host == "" {
        return errors.New("redirect_target: host must not be empty")
    }
    return nil
}

func errorResponse(msg string) gin.H {
    return gin.H{"error": msg}
}
