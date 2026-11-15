package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// maxBody is the largest request accepted. external-dns caps bodies at 32 MiB
// by default (about 60 000 records), so this is its limit, not a new one.
const maxBody = 32 << 20

// Provider is what the routes call. The implementation lives in
// internal/provider.
type Provider interface {
	Domains(ctx context.Context) ([]string, error)
	Records(ctx context.Context) ([]*Endpoint, error)
	AdjustEndpoints(ctx context.Context, in []*Endpoint) ([]*Endpoint, error)
	ApplyChanges(ctx context.Context, ch *Changes) error
}

// IsPermanent tells the server which ApplyChanges failures are answered with
// a 4xx (not retried) instead of a 5xx (retried).
type IsPermanent func(error) bool

// NewHandler is the provider API, meant to listen on localhost only.
func NewHandler(p Provider, permanent IsPermanent, logger *slog.Logger) http.Handler {
	h := &handler{p: p, permanent: permanent, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", h.negotiate)
	mux.HandleFunc("GET /records", h.records)
	mux.HandleFunc("POST /records", h.applyChanges)
	mux.HandleFunc("POST /adjustendpoints", h.adjustEndpoints)
	return mux
}

// NewHealthHandler answers the probes. It does not call the API: a dns-api
// outage must not get the pod restarted, external-dns already reports it.
func NewHealthHandler() http.Handler {
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}
	mux.HandleFunc("GET /healthz", ok)
	mux.HandleFunc("GET /readyz", ok)
	return mux
}

type handler struct {
	p         Provider
	permanent IsPermanent
	logger    *slog.Logger
}

func (h *handler) negotiate(w http.ResponseWriter, r *http.Request) {
	domains, err := h.p.Domains(r.Context())
	if err != nil {
		h.fail(w, "negotiate", http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, DomainFilter{Include: domains, Filters: domains})
}

func (h *handler) records(w http.ResponseWriter, r *http.Request) {
	eps, err := h.p.Records(r.Context())
	if err != nil {
		h.fail(w, "records", http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, eps)
}

func (h *handler) adjustEndpoints(w http.ResponseWriter, r *http.Request) {
	var in []*Endpoint
	if !h.decode(w, r, &in) {
		return
	}
	out, err := h.p.AdjustEndpoints(r.Context(), in)
	if err != nil {
		h.fail(w, "adjustendpoints", http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) applyChanges(w http.ResponseWriter, r *http.Request) {
	var ch Changes
	if !h.decode(w, r, &ch) {
		return
	}
	if err := h.p.ApplyChanges(r.Context(), &ch); err != nil {
		status := http.StatusInternalServerError
		if h.permanent != nil && h.permanent(err) {
			status = http.StatusBadRequest
		}
		h.fail(w, "applychanges", status, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		status := http.StatusBadRequest
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			status = http.StatusRequestEntityTooLarge
		}
		h.fail(w, "decode", status, err)
		return false
	}
	return true
}

// fail logs the error and answers with a short plain-text body. external-dns
// drains at most 1 MiB of an error body, and the useful detail is in our log.
func (h *handler) fail(w http.ResponseWriter, op string, status int, err error) {
	h.logger.Error("request failed", "op", op, "status", status, "error", err)
	msg := err.Error()
	if len(msg) > 4096 {
		msg = msg[:4096]
	}
	http.Error(w, msg, status)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", MediaType)
	w.Header().Set("Vary", "Content-Type")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
