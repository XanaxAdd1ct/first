package main

import (
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "io"
    "log/slog"
    "net/http"
    "net/http/httptest"

    "testing"
    "time"

    "github.com/prometheus/client_golang/prometheus"
)

const (
    testAdminToken = "test-admin-token-that-is-long-enough!!"
    testSecret     = "test-hmac-secret-that-is-32-chars!!"
    testDomain     = "example.com"
    testRedirect   = "https://redirect.example.com"
)

type mockStorage struct {
    domain  *DomainConfig
    err     error
    pingErr error
}

func (m *mockStorage) GetDomain(_ context.Context) (*DomainConfig, error) {
    if m.err != nil {
        return nil, m.err
    }
    if m.domain == nil {
        return nil, ErrNotFound
    }
    return m.domain, nil
}

func (m *mockStorage) UpdateDomain(_ context.Context, cfg *DomainConfig) (*DomainConfig, error) {
    if m.err != nil {
        return nil, m.err
    }
    cfg.Version++
    cfg.UpdatedAt = time.Now()
    m.domain = cfg
    return cfg, nil
}

func (m *mockStorage) Ping(_ context.Context) error {
    return m.pingErr
}

func (m *mockStorage) Close() error {
    return nil
}

func newTestServer(t *testing.T, store Storage) *Server {
    t.Helper()

    kr, err := NewKeyRing(testSecret)
    if err != nil {
        t.Fatalf("NewKeyRing: %v", err)
    }

    cfg := &APIConfig{
        AdminToken:      testAdminToken,
        DefaultDomain:   testDomain,
        DefaultRedirect: testRedirect,
    }

    log := slog.New(slog.NewTextHandler(io.Discard, nil))
    reg := prometheus.NewRegistry()

    srv, err := New(cfg, store, kr, log, reg)
    if err != nil {
        t.Fatalf("api.New: %v", err)
    }
    return srv
}

func doRequest(t *testing.T, srv http.Handler, method, path string, body interface{}, token string) *httptest.ResponseRecorder {
    t.Helper()

    var buf bytes.Buffer
    if body != nil {
        if err := json.NewEncoder(&buf).Encode(body); err != nil {
            t.Fatalf("encode body: %v", err)
        }
    }

    req := httptest.NewRequest(method, path, &buf)
    req.Header.Set("Content-Type", "application/json")
    if token != "" {
        req.Header.Set("Authorization", "Bearer "+token)
    }

    rr := httptest.NewRecorder()
    srv.ServeHTTP(rr, req)
    return rr
}

func TestHealth_OK(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    rr := doRequest(t, srv, http.MethodGet, "/health", nil, "")
    if rr.Code != http.StatusOK {
        t.Errorf("want 200, got %d", rr.Code)
    }
}

func TestHealth_RedisUnavailable(t *testing.T) {
    store := &mockStorage{pingErr: errors.New("connection refused")}
    srv := newTestServer(t, store)
    rr := doRequest(t, srv, http.MethodGet, "/health", nil, "")
    if rr.Code != http.StatusServiceUnavailable {
        t.Errorf("want 503, got %d", rr.Code)
    }
}

func TestAgentCheckin_CreatesDefaultDomain(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/agent/checkin", nil, "")

    if rr.Code != http.StatusOK {
        t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
    }

    var resp map[string]interface{}
    if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
        t.Fatalf("decode response: %v", err)
    }
    if resp["action"] != "update_domain" {
        t.Errorf("action: want update_domain, got %v", resp["action"])
    }
    if resp["signature"] == "" {
        t.Error("signature must not be empty")
    }
}

func TestAgentCheckin_StorageError(t *testing.T) {
    store := &mockStorage{err: errors.New("redis down")}
    srv := newTestServer(t, store)
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/agent/checkin", nil, "")
    if rr.Code != http.StatusInternalServerError {
        t.Errorf("want 500, got %d", rr.Code)
    }
}

func TestAgentCheckin_ExistingDomain(t *testing.T) {
    store := &mockStorage{
        domain: &DomainConfig{
            PrimaryDomain:  testDomain,
            RedirectTarget: testRedirect,
            Version:        5,
        },
    }
    srv := newTestServer(t, store)
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/agent/checkin", nil, "")

    if rr.Code != http.StatusOK {
        t.Fatalf("want 200, got %d", rr.Code)
    }

    var resp map[string]interface{}
    json.NewDecoder(rr.Body).Decode(&resp)

    payload := resp["payload"].(map[string]interface{})
    if payload["version"].(float64) != 5 {
        t.Errorf("version: want 5, got %v", payload["version"])
    }
}

func TestAdminUpdateDomain_Unauthorized(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", nil, "")
    if rr.Code != http.StatusUnauthorized {
        t.Errorf("want 401, got %d", rr.Code)
    }
}

func TestAdminUpdateDomain_InvalidToken(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", nil, "wrong-token")
    if rr.Code != http.StatusForbidden {
        t.Errorf("want 403, got %d", rr.Code)
    }
}

func TestAdminUpdateDomain_Success(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{
        "primary_domain":  "new.example.com",
        "redirect_target": "https://new-redirect.example.com",
    }
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusOK {
        t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
    }
}

func TestAdminUpdateDomain_MissingFields(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})

    cases := []struct {
        name string
        body map[string]string
    }{
        {"missing primary_domain", map[string]string{"redirect_target": testRedirect}},
        {"missing redirect_target", map[string]string{"primary_domain": testDomain}},
        {"invalid domain", map[string]string{"primary_domain": "nodot", "redirect_target": testRedirect}},
        {"invalid redirect scheme", map[string]string{"primary_domain": testDomain, "redirect_target": "ftp://example.com"}},
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", tc.body, testAdminToken)
            if rr.Code != http.StatusBadRequest {
                t.Errorf("want 400, got %d: %s", rr.Code, rr.Body.String())
            }
        })
    }
}

func TestAdminUpdateDomain_StorageError(t *testing.T) {
    store := &mockStorage{err: errors.New("redis down")}
    srv := newTestServer(t, store)
    body := map[string]string{
        "primary_domain":  testDomain,
        "redirect_target": testRedirect,
    }
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusInternalServerError {
        t.Errorf("want 500, got %d", rr.Code)
    }
}

func TestAdminRotateKey_Success(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{
        "new_secret": "new-32-character-secret!!!!!!!!!",
    }
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/rotate_key", body, testAdminToken)
    if rr.Code != http.StatusOK {
        t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
    }

    var resp map[string]interface{}
    json.NewDecoder(rr.Body).Decode(&resp)
    if resp["key_id"] == nil {
        t.Error("response must contain key_id")
    }
}

func TestAdminRotateKey_ShortSecret(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{"new_secret": "short"}
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/rotate_key", body, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("want 400, got %d", rr.Code)
    }
}

func TestAdminRotateKey_MissingSecret(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/rotate_key", map[string]string{}, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("want 400, got %d", rr.Code)
    }
}

func TestNew_InvalidConfig(t *testing.T) {
    kr, _ := NewKeyRing(testSecret)
    log := slog.New(slog.NewTextHandler(io.Discard, nil))
    reg := prometheus.NewRegistry()

    cases := []struct {
        name string
        cfg  *APIConfig
    }{
        {"nil config", nil},
        {"short admin token", &APIConfig{AdminToken: "short"}},
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            _, err := New(tc.cfg, &mockStorage{}, kr, log, reg)
            if err == nil {
                t.Error("expected error, got nil")
            }
        })
    }
}
func TestValidateDomain_Wildcard(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{
        "primary_domain":  "*.example.com",
        "redirect_target": testRedirect,
    }
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusOK {
        t.Errorf("wildcard domain: want 200, got %d: %s", rr.Code, rr.Body.String())
    }
}

func TestValidateDomain_LabelTooLong(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    long := ""
    for i := 0; i < 64; i++ {
        long += "a"
    }
    long += ".com"
    body := map[string]string{
        "primary_domain":  long,
        "redirect_target": testRedirect,
    }
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("long label: want 400, got %d", rr.Code)
    }
}

func TestValidateDomain_LeadingHyphen(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{
        "primary_domain":  "-bad.example.com",
        "redirect_target": testRedirect,
    }
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("leading hyphen: want 400, got %d", rr.Code)
    }
}

func TestValidateDomain_TrailingHyphen(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{
        "primary_domain":  "bad-.example.com",
        "redirect_target": testRedirect,
    }
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("trailing hyphen: want 400, got %d", rr.Code)
    }
}

func TestValidateDomain_EmptyLabel(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{
        "primary_domain":  "bad..example.com",
        "redirect_target": testRedirect,
    }
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("empty label: want 400, got %d", rr.Code)
    }
}

func TestValidateRedirectURL_EmptyHost(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{
        "primary_domain":  testDomain,
        "redirect_target": "https://",
    }
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("empty host: want 400, got %d: %s", rr.Code, rr.Body.String())
    }
}

func TestAdminRotateKey_RotateError(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{"new_secret": ""}
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/rotate_key", body, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("empty secret rotate: want 400, got %d", rr.Code)
    }
}

func TestNew_NilArgs(t *testing.T) {
    kr, _ := NewKeyRing(testSecret)
    log := slog.New(slog.NewTextHandler(io.Discard, nil))
    reg := prometheus.NewRegistry()
    cfg := &APIConfig{
        AdminToken:      testAdminToken,
        DefaultDomain:   testDomain,
        DefaultRedirect: testRedirect,
    }
    cases := []struct {
        name  string
        store Storage
        kr    KeyRinger
        log   *slog.Logger
    }{
        {"nil store",   nil,            kr,  log},
        {"nil keyring", &mockStorage{}, nil, log},
        {"nil logger",  &mockStorage{}, kr,  nil},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            _, err := New(cfg, tc.store, tc.kr, tc.log, reg)
            if err == nil {
                t.Error("expected error, got nil")
            }
        })
    }
}

func TestValidateDomain_InvalidChars(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{"primary_domain": "bad domain.com", "redirect_target": testRedirect}
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("space in domain: want 400, got %d", rr.Code)
    }
}

func TestValidateDomain_WildcardOnly(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{"primary_domain": "*.", "redirect_target": testRedirect}
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("wildcard only: want 400, got %d", rr.Code)
    }
}

func TestValidateRedirectURL_InvalidURL(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{"primary_domain": testDomain, "redirect_target": "://no-scheme"}
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("invalid URL: want 400, got %d", rr.Code)
    }
}

func TestVerify_KeyNotFound(t *testing.T) {
    kr, err := NewKeyRing(testSecret)
    if err != nil { t.Fatal(err) }
    err = kr.Verify(map[string]interface{}{"k": "v"}, "sig", 9999)
    if !errors.Is(err, ErrKeyNotFound) {
        t.Errorf("want ErrKeyNotFound, got %v", err)
    }
}

func TestVerify_KeyExpired(t *testing.T) {
    kr, err := NewKeyRing(testSecret)
    if err != nil { t.Fatal(err) }
    kr.mu.Lock()
    entry := kr.keys[kr.currentID]
    entry.validUntil = time.Now().Add(-time.Hour * 24 * 365)
    kr.keys[kr.currentID] = entry
    kr.mu.Unlock()
    err = kr.Verify(map[string]interface{}{"k": "v"}, "sig", kr.CurrentID())
    if !errors.Is(err, ErrKeyExpired) {
        t.Errorf("want ErrKeyExpired, got %v", err)
    }
}

func TestEvictStale_RemovesExpiredKey(t *testing.T) {
    kr, err := NewKeyRing(testSecret)
    if err != nil { t.Fatal(err) }
    if err := kr.Rotate("new-32-character-secret!!!!!!!!!"); err != nil {
        t.Fatal(err)
    }
    kr.mu.Lock()
    oldID := -1
    for id := range kr.keys {
        if id != kr.currentID {
            oldID = id
            entry := kr.keys[id]
            entry.validUntil = time.Now().Add(-time.Hour * 24 * 365)
            kr.keys[id] = entry
        }
    }
    kr.mu.Unlock()
    if oldID == -1 { t.Fatal("no old key found after rotate") }
    kr.mu.Lock()
    kr.evictStale(time.Now())
    _, exists := kr.keys[oldID]
    kr.mu.Unlock()
    if exists { t.Error("stale key was not evicted") }
}

func TestSign_MissingCurrentKey(t *testing.T) {
    kr, err := NewKeyRing(testSecret)
    if err != nil { t.Fatal(err) }
    kr.mu.Lock()
    delete(kr.keys, kr.currentID)
    kr.mu.Unlock()
    _, _, err = kr.Sign(map[string]interface{}{"k": "v"})
    if err == nil { t.Error("expected error when current key missing, got nil") }
}

func TestSign_UnmarshalablePayload(t *testing.T) {
    kr, _ := NewKeyRing(testSecret)
    payload := map[string]interface{}{"key": make(chan int)}
    _, _, err := kr.Sign(payload)
    if err == nil { t.Error("expected error for unmarshalable payload, got nil") }
}

func TestVerify_UnmarshalablePayload(t *testing.T) {
    kr, _ := NewKeyRing(testSecret)
    payload := map[string]interface{}{"key": make(chan int)}
    err := kr.Verify(payload, "sig", kr.CurrentID())
    if err == nil { t.Error("expected error for unmarshalable payload, got nil") }
}

func TestValidateDomain_NoDot(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{"primary_domain": "nodot", "redirect_target": testRedirect}
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("no dot: want 400, got %d", rr.Code)
    }
}

func TestValidateRedirectURL_EmptyTarget(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{"primary_domain": testDomain, "redirect_target": ""}
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("empty redirect: want 400, got %d", rr.Code)
    }
}

func TestValidateDomain_Direct(t *testing.T) {
    if err := validateDomain(""); err == nil {
        t.Error("expected error for empty domain, got nil")
    }
}

func TestValidateRedirectURL_Direct(t *testing.T) {
    if err := validateRedirectURL(""); err == nil {
        t.Error("expected error for empty URL, got nil")
    }
}

// --- mock KeyRinger ---

type mockKeyRing struct {
    signErr  error
    verifyErr error
    rotateErr error
    realKR   KeyRinger
}

func (m *mockKeyRing) Sign(payload map[string]interface{}) (string, int, error) {
    if m.signErr != nil {
        return "", 0, m.signErr
    }
    return m.realKR.Sign(payload)
}
func (m *mockKeyRing) Verify(payload map[string]interface{}, sig string, keyID int) error {
    if m.verifyErr != nil {
        return m.verifyErr
    }
    return m.realKR.Verify(payload, sig, keyID)
}
func (m *mockKeyRing) Rotate(newSecret string) error {
    if m.rotateErr != nil {
        return m.rotateErr
    }
    return m.realKR.Rotate(newSecret)
}
func (m *mockKeyRing) CurrentID() int {
    return m.realKR.CurrentID()
}

func newTestServerWithKR(t *testing.T, store Storage, kr KeyRinger) *Server {
    t.Helper()
    log := slog.New(slog.NewTextHandler(io.Discard, nil))
    reg := prometheus.NewRegistry()
    cfg := &APIConfig{
        AdminToken:      testAdminToken,
        DefaultDomain:   testDomain,
        DefaultRedirect: testRedirect,
    }
    srv, err := New(cfg, store, kr, log, reg)
    if err != nil {
        t.Fatalf("New: %v", err)
    }
    return srv
}

// --- тесты ---

func TestCheckin_SignError(t *testing.T) {
    realKR, _ := NewKeyRing(testSecret)
    kr := &mockKeyRing{signErr: errors.New("sign failed"), realKR: realKR}
    store := &mockStorage{domain: &DomainConfig{
        PrimaryDomain:  testDomain,
        RedirectTarget: testRedirect,
    }}
    srv := newTestServerWithKR(t, store, kr)
    body := map[string]string{"domain": testDomain}
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/agent/checkin", body, "")
    if rr.Code != http.StatusInternalServerError {
        t.Errorf("sign error: want 500, got %d", rr.Code)
    }
}

func TestAdminRotateKey_RotateKeyError(t *testing.T) {
    realKR, _ := NewKeyRing(testSecret)
    kr := &mockKeyRing{rotateErr: errors.New("rotate failed"), realKR: realKR}
    srv := newTestServerWithKR(t, &mockStorage{}, kr)
    body := map[string]string{"new_secret": "this-is-a-32-character-secret!!!"}
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/rotate_key", body, testAdminToken)
    if rr.Code != http.StatusInternalServerError {
        t.Errorf("rotate error: want 500, got %d", rr.Code)
    }
}

func TestIsValidLabel_InvalidChar(t *testing.T) {
    srv := newTestServer(t, &mockStorage{})
    body := map[string]string{"primary_domain": "bad_domain.com", "redirect_target": testRedirect}
    rr := doRequest(t, srv, http.MethodPost, "/api/v1/admin/update_domain", body, testAdminToken)
    if rr.Code != http.StatusBadRequest {
        t.Errorf("invalid char: want 400, got %d", rr.Code)
    }
}

func TestNewServerMetrics_Error(t *testing.T) {
    log := slog.New(slog.NewTextHandler(io.Discard, nil))
    kr, _ := NewKeyRing(testSecret)
    cfg := &APIConfig{
        AdminToken:      testAdminToken,
        DefaultDomain:   testDomain,
        DefaultRedirect: testRedirect,
    }
    reg := prometheus.NewRegistry()
    // Первый сервер регистрирует метрики
    _, err := New(cfg, &mockStorage{}, kr, log, reg)
    if err != nil {
        t.Fatalf("first New: %v", err)
    }
    // Второй с тем же registry — метрики уже зарегистрированы -> ошибка
    _, err = New(cfg, &mockStorage{}, kr, log, reg)
    if err == nil {
        t.Error("expected error on duplicate metrics registration, got nil")
    }
}

func TestRateLimit_Exceeded(t *testing.T) {
    srv := newTestServer(t, &mockStorage{
        domain: &DomainConfig{
            PrimaryDomain:  testDomain,
            RedirectTarget: testRedirect,
        },
    })
    var limited bool
    for i := 0; i < 300; i++ {
        rr := doRequest(t, srv, http.MethodGet, "/api/v1/health", nil, "")
        if rr.Code == http.StatusTooManyRequests {
            limited = true
            break
        }
    }
    if !limited {
        t.Error("expected 429 after many requests, never got it")
    }
}
