package main

// Local API auth (2026-11-07). The REST API binds loopback, but every process on the host used to be able to send
// as this WhatsApp line. With WHATSAPP_API_TOKENS_FILE set, /api/send, /api/typing, /api/react and /api/download
// need "Authorization: Bearer <token>", and a token may be scoped to a list of chat JIDs (the agents' token sends
// only to their own groups). Unset = no auth (the upstream behaviour). The file, one caller per line:
//
//	<name> <token> <scope>        scope = "*" or jid1,jid2,...   (# comments and blank lines ignored)
//
// It is re-read when its mtime changes, so a token can be rotated without a restart. The outbound webhook carries
// WEBHOOK_TOKEN as a bearer when set, so the receiver can tell the bridge from any other local process.

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type apiToken struct {
	name  string
	token string
	scope map[string]bool // nil = any recipient
}

type apiAuth struct {
	path    string
	mu      sync.Mutex
	mtime   time.Time
	tokens  []apiToken
	loadErr error
}

func newAPIAuth(path string) *apiAuth {
	a := &apiAuth{path: path}
	a.reload()
	return a
}

func (a *apiAuth) reload() {
	st, err := os.Stat(a.path)
	if err != nil {
		a.loadErr = err
		a.tokens = nil
		return
	}
	if st.ModTime().Equal(a.mtime) && a.loadErr == nil {
		return
	}
	f, err := os.Open(a.path)
	if err != nil {
		a.loadErr = err
		a.tokens = nil
		return
	}
	defer func() { _ = f.Close() }()
	var out []apiToken
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 || len(parts[1]) < 16 {
			continue // a short token is no token
		}
		t := apiToken{name: parts[0], token: parts[1]}
		if parts[2] != "*" {
			t.scope = map[string]bool{}
			for _, j := range strings.Split(parts[2], ",") {
				if j = strings.TrimSpace(j); j != "" {
					t.scope[j] = true
				}
			}
		}
		out = append(out, t)
	}
	a.tokens, a.mtime, a.loadErr = out, st.ModTime(), sc.Err()
}

// check answers whether the request may act on recipient ("" = no recipient involved). It writes the refusal itself
// and returns false; the caller just returns. Constant-time over every token (no early exit on a match).
func (a *apiAuth) check(w http.ResponseWriter, r *http.Request, recipient string) bool {
	if a == nil {
		return true
	}
	a.mu.Lock()
	a.reload()
	tokens, loadErr := a.tokens, a.loadErr
	a.mu.Unlock()
	if loadErr != nil || len(tokens) == 0 {
		http.Error(w, "api auth is configured but no token can be read", http.StatusServiceUnavailable)
		return false
	}
	presented := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
	var found *apiToken
	for i := range tokens {
		if subtle.ConstantTimeCompare([]byte(tokens[i].token), []byte(presented)) == 1 {
			found = &tokens[i]
		}
	}
	if found == nil || presented == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if recipient != "" && found.scope != nil && !found.scope[recipient] {
		fmt.Printf("api: token %q refused for a recipient outside its scope\n", found.name)
		http.Error(w, "this token may not address that chat", http.StatusForbidden)
		return false
	}
	return true
}

// apiAuthFromEnv: WHATSAPP_API_TOKENS_FILE, or nil (open API, as upstream).
func apiAuthFromEnv() *apiAuth {
	p := strings.TrimSpace(os.Getenv("WHATSAPP_API_TOKENS_FILE"))
	if p == "" {
		return nil
	}
	a := newAPIAuth(p)
	if a.loadErr != nil {
		fmt.Printf("api auth: tokens file %s unreadable (%v): every authenticated route answers 503 until it is\n", p, a.loadErr)
	} else {
		fmt.Printf("api auth: %d token(s) from %s\n", len(a.tokens), p)
	}
	return a
}
