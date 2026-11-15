package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type stubProvider struct {
	applyErr error
	got      *Changes
}

func (s *stubProvider) Domains(context.Context) ([]string, error) {
	return []string{"example.com"}, nil
}

func (s *stubProvider) Records(context.Context) ([]*Endpoint, error) {
	return []*Endpoint{{DNSName: "www.example.com", RecordType: "A", Targets: []string{"192.0.2.1"}, RecordTTL: 300}}, nil
}

func (s *stubProvider) AdjustEndpoints(_ context.Context, in []*Endpoint) ([]*Endpoint, error) {
	return in, nil
}

func (s *stubProvider) ApplyChanges(_ context.Context, ch *Changes) error {
	s.got = ch
	return s.applyErr
}

var errPerm = errors.New("perm")

func serve(t *testing.T, p Provider, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewHandler(p, func(err error) bool { return errors.Is(err, errPerm) }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Accept", MediaType)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestNegotiate(t *testing.T) {
	rec := serve(t, &stubProvider{}, http.MethodGet, "/", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != MediaType {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	var df map[string][]string
	if err := json.Unmarshal(rec.Body.Bytes(), &df); err != nil {
		t.Fatal(err)
	}
	if df["include"][0] != "example.com" || df["filters"][0] != "example.com" {
		t.Fatalf("domain filter = %s", rec.Body)
	}
}

func TestApplyChangesWireFormat(t *testing.T) {
	p := &stubProvider{}
	body := `{"create":[{"dnsName":"a.example.com","targets":["192.0.2.1"],"recordType":"A","recordTTL":60}],
	          "updateOld":[],"updateNew":[],"delete":[{"dnsName":"b.example.com","recordType":"TXT","targets":["\"x\""]}]}`
	rec := serve(t, p, http.MethodPost, "/records", body)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if len(p.got.Create) != 1 || p.got.Create[0].RecordTTL != 60 || p.got.Delete[0].Targets[0] != `"x"` {
		t.Fatalf("decoded %+v", p.got)
	}
}

func TestApplyChangesStatus(t *testing.T) {
	if rec := serve(t, &stubProvider{applyErr: errPerm}, http.MethodPost, "/records", `{}`); rec.Code != http.StatusBadRequest {
		t.Errorf("permanent failure: %d, want 400", rec.Code)
	}
	if rec := serve(t, &stubProvider{applyErr: errors.New("x")}, http.MethodPost, "/records", `{}`); rec.Code != http.StatusInternalServerError {
		t.Errorf("transient failure: %d, want 500", rec.Code)
	}
	if rec := serve(t, &stubProvider{}, http.MethodPost, "/records", `{`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d, want 400", rec.Code)
	}
}
