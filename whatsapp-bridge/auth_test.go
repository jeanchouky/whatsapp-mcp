package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAPIAuth_TokensScopeAndRotation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tokens")
	if err := os.WriteFile(p, []byte("# callers\nbrain fake-brain-token-0000000000 *\nagents fake-agents-token-000000000 g1@g.us,g2@g.us\nshort abc *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := newAPIAuth(p)
	if len(a.tokens) != 2 {
		t.Fatalf("want 2 tokens (the short one dropped), got %d", len(a.tokens))
	}
	try := func(tok, recipient string) int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/api/send", nil)
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		if a.check(w, r, recipient) {
			return 200
		}
		return w.Code
	}
	if c := try("", "x@s.whatsapp.net"); c != 401 {
		t.Errorf("no token: want 401, got %d", c)
	}
	if c := try("fake-brain-token-0000000000", "anyone@s.whatsapp.net"); c != 200 {
		t.Errorf("brain token, any recipient: want 200, got %d", c)
	}
	if c := try("fake-agents-token-000000000", "g1@g.us"); c != 200 {
		t.Errorf("agents token, own group: want 200, got %d", c)
	}
	if c := try("fake-agents-token-000000000", "someone@s.whatsapp.net"); c != 403 {
		t.Errorf("agents token, a DM: want 403, got %d", c)
	}
	if c := try("fake-agents-token-000000000", ""); c != 200 {
		t.Errorf("agents token, no recipient (download): want 200, got %d", c)
	}
	if c := try("abc", "g1@g.us"); c != 401 {
		t.Errorf("the dropped short token: want 401, got %d", c)
	}
	// rotation: rewrite the file → the old token stops, the new one works (mtime moves on)
	if err := os.WriteFile(p, []byte("brain fake-brain-token-1111111111 *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(p, a.mtime.Add(2e9), a.mtime.Add(2e9))
	if c := try("fake-brain-token-0000000000", "x@g.us"); c != 401 {
		t.Errorf("rotated-out token: want 401, got %d", c)
	}
	if c := try("fake-brain-token-1111111111", "x@g.us"); c != 200 {
		t.Errorf("new token: want 200, got %d", c)
	}
	// an unreadable file fails closed
	os.Remove(p)
	if c := try("fake-brain-token-1111111111", "x@g.us"); c != 503 {
		t.Errorf("missing tokens file: want 503, got %d", c)
	}
	// nil auth = open API (upstream)
	var open *apiAuth
	w := httptest.NewRecorder()
	if !open.check(w, httptest.NewRequest(http.MethodPost, "/api/send", nil), "x") {
		t.Error("nil auth must allow")
	}
}
