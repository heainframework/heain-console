package console

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeCore struct{ calls int }

func (f *fakeCore) Do(context.Context, string, string, http.Header, any, any) (int, error) {
	f.calls++
	return 200, nil
}

func ui(c *Console, p string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/ui/"+p, nil)
	r.SetPathValue("path", p)
	w := httptest.NewRecorder()
	c.UI(w, r)
	return w
}

func TestUI(t *testing.T) {
	c := &Console{Core: &fakeCore{}}
	for p, ct := range map[string]string{"": "text/html", "index.html": "text/html", "app.js": "javascript", "app.css": "text/css"} {
		w := ui(c, p)
		if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), ct) || w.Header().Get("Content-Security-Policy") != CSP ||
			w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("%q: %d %v", p, w.Code, w.Header())
		}
	}
	for _, p := range []string{"../console.go", "nope.html", "/etc/passwd", "ui/app.js"} {
		if w := ui(c, p); w.Code != 404 {
			t.Fatalf("%q: %d", p, w.Code)
		}
	}
	// no inline script or style, nothing from elsewhere: the CSP allows only this origin
	idx := ui(c, "index.html").Body.String()
	if strings.Contains(idx, "<script>") || strings.Contains(idx, "style=") || strings.Contains(idx, "http://") || strings.Contains(idx, "https://") {
		t.Fatal("index.html must hold no inline script or style and load nothing from elsewhere")
	}
	js := ui(c, "app.js").Body.String()
	if strings.Contains(js, "innerHTML") || strings.Contains(js, "eval(") || strings.Contains(js, "new Function") {
		t.Fatal("app.js must not build HTML from strings or evaluate code")
	}
	if !strings.Contains(CSP, "default-src 'none'") || !strings.Contains(CSP, "frame-ancestors 'none'") || strings.Contains(CSP, "unsafe") {
		t.Fatal("CSP")
	}
}

func TestRelayRefusals(t *testing.T) {
	f := &fakeCore{}
	c := &Console{Core: f}
	// an app (no signed-in person) is refused before core is asked
	r := httptest.NewRequest("GET", "/v1/core/whoami", nil)
	r.SetPathValue("path", "whoami")
	w := httptest.NewRecorder()
	c.Relay(w, r)
	if w.Code != 401 || !strings.Contains(w.Body.String(), "sign_in_required") || f.calls != 0 {
		t.Fatalf("no person: %d %s", w.Code, w.Body.String())
	}
	if _, err := gatewayChain(httptest.NewRequest("GET", "/", nil)); err == nil {
		t.Fatal("no TLS")
	}
	cert := &x509.Certificate{Raw: []byte{1, 2, 3}}
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert, cert}}
	s, err := gatewayChain(r2)
	b, _ := base64.StdEncoding.DecodeString(s)
	if err != nil || strings.Count(string(b), "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("chain: %v %s", err, b)
	}
}
