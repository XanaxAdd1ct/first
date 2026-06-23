package main

import (
    "testing"
)

const validSecret = "this-is-a-32-character-secret!!"

func newKeyRing(t *testing.T) *KeyRing {
    t.Helper()
    kr, err := NewKeyRing(validSecret)
    if err != nil {
        t.Fatalf("NewKeyRing: %v", err)
    }
    return kr
}

func validPayload() map[string]interface{} {
    return map[string]interface{}{
        "domain":  "example.com",
        "version": 1,
    }
}

func TestNewKeyRing_EmptySecret(t *testing.T) {
    _, err := NewKeyRing("")
    if err == nil {
        t.Fatal("expected error for empty secret, got nil")
    }
}



func TestNewKeyRing_ValidSecret(t *testing.T) {
    kr, err := NewKeyRing(validSecret)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if kr.CurrentID() != 1 {
        t.Errorf("CurrentID: want 1, got %d", kr.CurrentID())
    }
}

func TestSign_Success(t *testing.T) {
    kr := newKeyRing(t)

    sig, keyID, err := kr.Sign(validPayload())
    if err != nil {
        t.Fatalf("Sign: %v", err)
    }
    if sig == "" {
        t.Error("Sign: signature is empty")
    }
    if keyID != 1 {
        t.Errorf("Sign: keyID want 1, got %d", keyID)
    }
}

func TestSign_EmptyPayload(t *testing.T) {
    kr := newKeyRing(t)

    sig, keyID, err := kr.Sign(map[string]interface{}{})
    if err != nil {
        t.Fatalf("Sign empty payload: %v", err)
    }
    if sig == "" {
        t.Error("Sign: signature is empty for empty payload")
    }
    if keyID != 1 {
        t.Errorf("Sign: keyID want 1, got %d", keyID)
    }
}

func TestVerify_ValidSignature(t *testing.T) {
    kr := newKeyRing(t)
    payload := validPayload()

    sig, keyID, err := kr.Sign(payload)
    if err != nil {
        t.Fatalf("Sign: %v", err)
    }
    if err := kr.Verify(payload, sig, keyID); err != nil {
        t.Errorf("Verify: unexpected error: %v", err)
    }
}

func TestVerify_WrongSignature(t *testing.T) {
    kr := newKeyRing(t)
    payload := validPayload()

    _, keyID, err := kr.Sign(payload)
    if err != nil {
        t.Fatalf("Sign: %v", err)
    }
    if err := kr.Verify(payload, "invalidsignature", keyID); err == nil {
        t.Error("Verify: expected error for wrong signature, got nil")
    }
}

func TestVerify_WrongKeyID(t *testing.T) {
    kr := newKeyRing(t)
    payload := validPayload()

    sig, _, err := kr.Sign(payload)
    if err != nil {
        t.Fatalf("Sign: %v", err)
    }
    if err := kr.Verify(payload, sig, 999); err == nil {
        t.Error("Verify: expected error for unknown keyID, got nil")
    }
}

func TestVerify_TamperedPayload(t *testing.T) {
    kr := newKeyRing(t)
    payload := validPayload()

    sig, keyID, err := kr.Sign(payload)
    if err != nil {
        t.Fatalf("Sign: %v", err)
    }

    tampered := map[string]interface{}{
        "domain":  "evil.com",
        "version": 1,
    }
    if err := kr.Verify(tampered, sig, keyID); err == nil {
        t.Error("Verify: expected error for tampered payload, got nil")
    }
}

func TestRotate_UpdatesCurrentID(t *testing.T) {
    kr := newKeyRing(t)

    if err := kr.Rotate("new-32-character-secret!!!!!!!!!"); err != nil {
        t.Fatalf("Rotate: %v", err)
    }
    if kr.CurrentID() != 2 {
        t.Errorf("CurrentID after rotate: want 2, got %d", kr.CurrentID())
    }
}

func TestRotate_EmptySecret(t *testing.T) {
    kr := newKeyRing(t)

    if err := kr.Rotate(""); err == nil {
        t.Error("Rotate: expected error for empty secret, got nil")
    }
}

func TestRotate_OldKeyStillVerifies(t *testing.T) {
    kr := newKeyRing(t)
    payload := validPayload()

    sig, keyID, err := kr.Sign(payload)
    if err != nil {
        t.Fatalf("Sign: %v", err)
    }

    if err := kr.Rotate("new-32-character-secret!!!!!!!!!"); err != nil {
        t.Fatalf("Rotate: %v", err)
    }

    if err := kr.Verify(payload, sig, keyID); err != nil {
        t.Errorf("Verify with old key after rotate: %v", err)
    }
}

func TestRotate_NewKeyVerifies(t *testing.T) {
    kr := newKeyRing(t)

    if err := kr.Rotate("new-32-character-secret!!!!!!!!!"); err != nil {
        t.Fatalf("Rotate: %v", err)
    }

    payload := validPayload()
    sig, keyID, err := kr.Sign(payload)
    if err != nil {
        t.Fatalf("Sign after rotate: %v", err)
    }
    if err := kr.Verify(payload, sig, keyID); err != nil {
        t.Errorf("Verify with new key: %v", err)
    }
}

func TestSign_DeterministicOutput(t *testing.T) {
    kr := newKeyRing(t)
    payload := validPayload()

    sig1, _, err := kr.Sign(payload)
    if err != nil {
        t.Fatalf("Sign first: %v", err)
    }
    sig2, _, err := kr.Sign(payload)
    if err != nil {
        t.Fatalf("Sign second: %v", err)
    }
    if sig1 != sig2 {
        t.Error("Sign: same payload produced different signatures")
    }
}

func TestSign_KeyOrderIndependent(t *testing.T) {
    kr := newKeyRing(t)

    p1 := map[string]interface{}{"a": 1, "b": 2}
    p2 := map[string]interface{}{"b": 2, "a": 1}

    sig1, id1, err := kr.Sign(p1)
    if err != nil {
        t.Fatalf("Sign p1: %v", err)
    }
    sig2, _, err := kr.Sign(p2)
    if err != nil {
        t.Fatalf("Sign p2: %v", err)
    }
    if sig1 != sig2 {
        t.Error("Sign: key order affected signature")
    }
    if err := kr.Verify(p2, sig1, id1); err != nil {
        t.Errorf("Verify cross-order: %v", err)
    }
}
func TestCanonicalJSON_UnmarshalableInput(t *testing.T) {
    ch := make(chan int)
    _, err := canonicalJSON(ch)
    if err == nil {
        t.Error("expected error for unmarshalable input, got nil")
    }
}