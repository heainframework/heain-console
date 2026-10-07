// Package console is heain-console (Step 5b, author decisions 2026-10-08):
// the web screens for heain-core's admin plane, served behind heain-gateway.
//
//   - GET /ui/{path...} serves the screens (plain HTML/JS embedded in the
//     binary, a strict Content-Security-Policy, no inline script, nothing
//     from elsewhere). heain-gateway exposes it as an anonymous route, so
//     the sign-in page loads before anyone has signed in.
//   - <GET|POST|PUT|DELETE> /v1/core/{path...} runs core's /v1/admin/<path>
//     as the signed-in person: the console relays the gateway's assertion
//     and the gateway instance's certificate to core's
//     /v1/app/admin/<path> (core Step 5b-1). Core decides everything: the
//     person's roles (roles.admins / roles.approvers, "user:<account>"),
//     four-eyes, P5, MFA (console.auth_methods). Only people reach it; an
//     app calling the console directly is refused.
//   - The screens call heain-gateway's /auth/* to sign in and heain-report's
//     exposed routes for dashboards themselves (same origin).
package console

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/heain"
)

//go:embed ui
var uiFS embed.FS

// CSP is the screens' page policy: everything from this origin only, no
// inline script or style, no framing, no plugins.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// MaxBody bounds a request relayed to core.
const MaxBody = 1 << 20

// Core is what the console needs from heain-core (heain-sdk's core client).
type Core interface {
	Do(ctx context.Context, method, path string, hdr http.Header, body, out any) (int, error)
}

// Console is heain-console.
type Console struct {
	Core Core
	Logf func(string, ...any)
}

// Register adds the endpoints to the app's server.
func (c *Console) Register(srv *heain.Server) error {
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	for pat, h := range map[string]http.HandlerFunc{
		"GET /ui/{path...}":         c.UI,
		"GET /v1/core/{path...}":    c.Relay,
		"POST /v1/core/{path...}":   c.Relay,
		"PUT /v1/core/{path...}":    c.Relay,
		"DELETE /v1/core/{path...}": c.Relay,
	} {
		if err := srv.HandleFunc(pat, h); err != nil {
			return err
		}
	}
	return nil
}

func fail(w http.ResponseWriter, code int, c, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": c, "message": msg}})
}

// UI serves the embedded screens.
func (c *Console) UI(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("path")
	if name == "" {
		name = "index.html"
	}
	if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(uiFS, "ui/"+path.Clean(name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ct := mime.TypeByExtension(path.Ext(name))
	if ct == "" {
		ct = "application/octet-stream"
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("Content-Security-Policy", CSP)
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}

// gatewayChain is the certificate chain the gateway presented on this
// connection, as PEM in base64 (core's X-Heain-User-Cert).
func gatewayChain(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("no client certificate on this connection")
	}
	var b bytes.Buffer
	for _, c := range r.TLS.PeerCertificates {
		_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// Relay runs /v1/admin/<path> on core as the signed-in person.
func (c *Console) Relay(w http.ResponseWriter, r *http.Request) {
	u := heain.UserOf(r.Context())
	if u == nil || u.Assertion == "" {
		fail(w, http.StatusUnauthorized, "sign_in_required", "only a person signed in through heain-gateway may use the console")
		return
	}
	p := r.PathValue("path")
	if p == "" || strings.Contains(p, "..") || strings.HasPrefix(p, "/") {
		fail(w, http.StatusBadRequest, "bad_request", "a /v1/admin path is needed")
		return
	}
	chain, err := gatewayChain(r)
	if err != nil {
		fail(w, http.StatusUnauthorized, "sign_in_required", err.Error())
		return
	}
	var body any
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		raw, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
		if err != nil || len(raw) > MaxBody {
			fail(w, http.StatusRequestEntityTooLarge, "too_large", "the request body is too large")
			return
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			raw = []byte("{}")
		}
		if !json.Valid(raw) {
			fail(w, http.StatusBadRequest, "bad_request", "the body must be JSON")
			return
		}
		body = json.RawMessage(raw)
	}
	target := "/v1/app/admin/" + p
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	hdr := http.Header{}
	hdr.Set("X-Heain-User", u.Assertion)
	hdr.Set("X-Heain-User-Cert", chain)
	if t := heain.TraceID(r.Context()); t != "" {
		hdr.Set(heain.HeaderTrace, t)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	var out json.RawMessage
	code, err := c.Core.Do(ctx, r.Method, target, hdr, body, &out)
	if err != nil {
		var ce *core.Error
		if errors.As(err, &ce) {
			code := ce.Code
			if code == "" {
				code = "http_" + http.StatusText(ce.Status)
			}
			fail(w, ce.Status, code, ce.Message)
			return
		}
		c.Logf("heain-console: core: %v", err)
		fail(w, http.StatusBadGateway, "core_unreachable", "heain-core did not answer")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if len(out) == 0 {
		out = json.RawMessage("{}")
	}
	w.WriteHeader(code)
	_, _ = w.Write(out)
}
