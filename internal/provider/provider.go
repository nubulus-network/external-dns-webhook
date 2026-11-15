// Package provider translates between external-dns endpoints and the record
// sets of dns-api. It has no state of its own beyond a short-lived list of
// zones: the records live on the name servers and are read on every cycle.
package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	nubulus "github.com/nubulus-network/nubulus-go"

	"github.com/nubulus-network/external-dns-webhook/internal/webhook"
)

// DNS is the slice of nubulus.DNSClient the provider uses. It is an interface
// so the tests can run against an in-memory zone.
type DNS interface {
	ListZones(ctx context.Context) ([]nubulus.Zone, error)
	ZoneContent(ctx context.Context, zone string) (*nubulus.ZoneContent, error)
	PutRRset(ctx context.Context, zone, name, rrtype string, ttl uint32, values []string) (*nubulus.RRset, error)
	DeleteRRset(ctx context.Context, zone, name, rrtype string) error
}

// TTL limits of dns-api. A TTL outside them is clamped in adjustendpoints
// instead of being refused on every cycle.
const (
	DefaultTTL = 300
	MinTTL     = 60
	MaxTTL     = 604800
)

// zoneCacheTTL is how long the list of zones is reused. Zones are added or
// removed by hand in the panel and change rarely; records are never cached.
const zoneCacheTTL = 5 * time.Minute

// forbiddenTypes are the types dns-api never lets anyone write. SOA is
// included because it is always the platform's.
var forbiddenTypes = map[string]bool{
	"SOA": true, "DNSKEY": true, "RRSIG": true, "NSEC": true, "NSEC3": true,
	"NSEC3PARAM": true, "CDS": true, "CDNSKEY": true, "DNAME": true,
}

// Provider is the webhook's view of one account.
type Provider struct {
	dns    DNS
	logger *slog.Logger
	now    func() time.Time

	mu        sync.Mutex
	zones     []string // active zones, without the trailing dot
	zonesRead time.Time
}

// New builds a provider on top of a dns-api client.
func New(dns DNS, logger *slog.Logger) *Provider {
	return &Provider{dns: dns, logger: logger, now: time.Now}
}

// ─────────────────────────────────────────────────────────────────────────────
// Zones
// ─────────────────────────────────────────────────────────────────────────────

// Domains is the domain filter: the active zones of the account.
func (p *Provider) Domains(ctx context.Context) ([]string, error) {
	return p.activeZones(ctx, false)
}

func (p *Provider) activeZones(ctx context.Context, refresh bool) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !refresh && p.zones != nil && p.now().Sub(p.zonesRead) < zoneCacheTTL {
		return p.zones, nil
	}
	all, err := p.dns.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	zones := make([]string, 0, len(all))
	for _, z := range all {
		// Pending and suspended zones refuse writes, and listing their
		// records would let external-dns plan changes that can only fail.
		if z.Status != "active" {
			continue
		}
		zones = append(zones, strings.TrimSuffix(strings.ToLower(z.Name), "."))
	}
	sort.Strings(zones)
	p.zones, p.zonesRead = zones, p.now()
	return zones, nil
}

// zoneFor returns the zone a name belongs to: the longest active zone that is
// the name itself or a suffix of it on a label boundary.
func zoneFor(zones []string, name string) string {
	best := ""
	for _, z := range zones {
		if (name == z || strings.HasSuffix(name, "."+z)) && len(z) > len(best) {
			best = z
		}
	}
	return best
}

// resolveZone is zoneFor with one refresh of the cached list on a miss, so a
// zone created a minute ago does not wait for the cache to expire.
func (p *Provider) resolveZone(ctx context.Context, name string) (string, error) {
	zones, err := p.activeZones(ctx, false)
	if err != nil {
		return "", err
	}
	if z := zoneFor(zones, name); z != "" {
		return z, nil
	}
	zones, err = p.activeZones(ctx, true)
	if err != nil {
		return "", err
	}
	return zoneFor(zones, name), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Records
// ─────────────────────────────────────────────────────────────────────────────

// Records reads every active zone and returns its record sets as endpoints.
//
// A zone that cannot be read fails the whole call. Leaving it out would tell
// external-dns that its records are gone, and it would plan to create them all
// again.
func (p *Provider) Records(ctx context.Context) ([]*webhook.Endpoint, error) {
	zones, err := p.activeZones(ctx, false)
	if err != nil {
		return nil, err
	}
	out := []*webhook.Endpoint{}
	for _, zone := range zones {
		content, err := p.dns.ZoneContent(ctx, zone)
		if err != nil {
			return nil, fmt.Errorf("reading zone %s: %w", zone, err)
		}
		for _, set := range content.RRsets {
			name := trimDot(strings.ToLower(set.Name))
			rrtype := strings.ToUpper(set.Type)
			// The SOA and the apex NS are the platform's. Showing them would
			// invite external-dns to treat them as records it could manage.
			if rrtype == "SOA" || (rrtype == "NS" && name == zone) {
				continue
			}
			targets := make([]string, 0, len(set.Values))
			for _, v := range set.Values {
				targets = append(targets, readTarget(rrtype, v))
			}
			sort.Strings(targets)
			out = append(out, &webhook.Endpoint{
				DNSName:    name,
				RecordType: rrtype,
				RecordTTL:  int64(set.TTL),
				Targets:    targets,
			})
		}
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// AdjustEndpoints
// ─────────────────────────────────────────────────────────────────────────────

// AdjustEndpoints brings the endpoints external-dns wants into exactly the form
// Records will return once they are written, and drops the ones dns-api would
// refuse. The second half matters as much as the first: a record that can
// never be written fails the whole batch on every cycle.
func (p *Provider) AdjustEndpoints(ctx context.Context, in []*webhook.Endpoint) ([]*webhook.Endpoint, error) {
	zones, err := p.activeZones(ctx, false)
	if err != nil {
		return nil, err
	}
	out := make([]*webhook.Endpoint, 0, len(in))
	for _, ep := range in {
		if ep == nil {
			continue
		}
		e := *ep
		e.DNSName = trimDot(strings.ToLower(strings.TrimSpace(e.DNSName)))
		e.RecordType = strings.ToUpper(strings.TrimSpace(e.RecordType))

		if reason := p.refusal(zones, &e); reason != "" {
			p.logger.Warn("endpoint not supported, ignoring it",
				"name", e.DNSName, "type", e.RecordType, "reason", reason)
			continue
		}

		e.RecordTTL = clampTTL(e.RecordTTL)
		e.Targets = normalizeTargets(e.RecordType, e.Targets)
		out = append(out, &e)
	}
	return out, nil
}

// refusal says why dns-api would refuse this endpoint, or "".
func (p *Provider) refusal(zones []string, e *webhook.Endpoint) string {
	if e.SetIdentifier != "" {
		return "routing policies (setIdentifier) are not supported"
	}
	if forbiddenTypes[e.RecordType] {
		return e.RecordType + " records are managed by the platform"
	}
	zone := zoneFor(zones, e.DNSName)
	if zone == "" {
		return "the name is not inside an active zone of the account"
	}
	if e.DNSName == zone && (e.RecordType == "NS" || e.RecordType == "CNAME") {
		return e.RecordType + " is not allowed at the zone apex"
	}
	return ""
}

func clampTTL(ttl int64) int64 {
	switch {
	case ttl <= 0:
		return DefaultTTL
	case ttl < MinTTL:
		return MinTTL
	case ttl > MaxTTL:
		return MaxTTL
	}
	return ttl
}

// normalizeTargets canonicalizes, deduplicates and sorts. An RRset is a set,
// and the primary returns it sorted, so the order carries no meaning.
func normalizeTargets(rrtype string, targets []string) []string {
	seen := make(map[string]bool, len(targets))
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		c := canonicalTarget(rrtype, t)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// canonicalTarget is the form a target takes on both sides of the comparison.
func canonicalTarget(rrtype, t string) string {
	if rrtype == "TXT" {
		return canonicalTXT(t)
	}
	t = strings.TrimSpace(t)
	switch rrtype {
	case "A", "AAAA":
		if addr, err := netip.ParseAddr(t); err == nil {
			return addr.String()
		}
		return t
	case "CNAME", "NS", "PTR":
		return trimDot(strings.ToLower(t))
	case "MX", "SRV":
		return mapLastField(t, func(s string) string { return trimDot(strings.ToLower(s)) })
	}
	return t
}

// readTarget turns a value read from the primary into the canonical form.
func readTarget(rrtype, v string) string {
	return canonicalTarget(rrtype, v)
}

// writeValue turns a canonical target into the value sent to dns-api: names
// fully qualified, TXT split into 255-byte strings.
func writeValue(rrtype, t string) string {
	switch rrtype {
	case "TXT":
		return splitTXT(t)
	case "CNAME", "NS", "PTR":
		return fqdn(t)
	case "MX", "SRV":
		return mapLastField(t, fqdn)
	}
	return t
}

// mapLastField applies f to the last whitespace-separated field, which is the
// target name in MX ("10 mail.example.com") and SRV ("0 5 443 host").
func mapLastField(s string, f func(string) string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return s
	}
	fields[len(fields)-1] = f(fields[len(fields)-1])
	return strings.Join(fields, " ")
}

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }

func fqdn(s string) string {
	if s == "" || s == "." || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// ─────────────────────────────────────────────────────────────────────────────
// ApplyChanges
// ─────────────────────────────────────────────────────────────────────────────

// ErrPermanent wraps a failure that retrying will not fix: the server answers
// it with a 4xx so external-dns does not retry it straight away.
var ErrPermanent = errors.New("permanent failure")

// ApplyChanges writes a plan.
//
// Deletes go first so that turning an A into a CNAME (or back) never trips the
// CNAME coexistence rule. UpdateOld is not needed: a PUT replaces the whole
// record set.
//
// The batch is not atomic: every change is attempted, and the call fails if
// any of them did. external-dns plans again on the next cycle, and PUT and
// DELETE are idempotent, so what was already applied is not applied twice.
func (p *Provider) ApplyChanges(ctx context.Context, ch *webhook.Changes) error {
	if ch == nil {
		return nil
	}
	var errs []error
	transient := false
	record := func(op string, e *webhook.Endpoint, err error) {
		if err == nil {
			p.logger.Info("record set "+op, "name", e.DNSName, "type", e.RecordType)
			return
		}
		p.logger.Error("record set "+op+" failed", "name", e.DNSName, "type", e.RecordType, "error", err)
		if isTransient(err) {
			transient = true
		}
		errs = append(errs, fmt.Errorf("%s %s %s: %w", op, e.RecordType, e.DNSName, err))
	}

	for _, e := range ch.Delete {
		if e == nil {
			continue
		}
		record("deleted", e, p.delete(ctx, e))
	}
	for _, list := range [][]*webhook.Endpoint{ch.UpdateNew, ch.Create} {
		for _, e := range list {
			if e == nil {
				continue
			}
			record("written", e, p.put(ctx, e))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	err := errors.Join(errs...)
	if transient {
		return err
	}
	return fmt.Errorf("%w: %w", ErrPermanent, err)
}

func (p *Provider) put(ctx context.Context, e *webhook.Endpoint) error {
	name := trimDot(strings.ToLower(e.DNSName))
	rrtype := strings.ToUpper(e.RecordType)
	zone, err := p.resolveZone(ctx, name)
	if err != nil {
		return err
	}
	if zone == "" {
		return fmt.Errorf("%w: %s is not inside an active zone", ErrPermanent, name)
	}
	targets := normalizeTargets(rrtype, e.Targets)
	if len(targets) == 0 {
		return fmt.Errorf("%w: no targets", ErrPermanent)
	}
	values := make([]string, 0, len(targets))
	for _, t := range targets {
		values = append(values, writeValue(rrtype, t))
	}
	_, err = p.dns.PutRRset(ctx, zone, fqdn(name), rrtype, uint32(clampTTL(e.RecordTTL)), values)
	return err
}

func (p *Provider) delete(ctx context.Context, e *webhook.Endpoint) error {
	name := trimDot(strings.ToLower(e.DNSName))
	rrtype := strings.ToUpper(e.RecordType)
	zone, err := p.resolveZone(ctx, name)
	if err != nil {
		return err
	}
	if zone == "" {
		// The zone is gone or no longer active, and so is the record as far
		// as this account is concerned.
		return nil
	}
	err = p.dns.DeleteRRset(ctx, zone, fqdn(name), rrtype)
	if nubulus.IsNotFound(err) {
		return nil
	}
	return err
}

// isTransient says whether a failure is worth retrying straight away: the
// network, the API or the primary failing, or a race lost twice. Validation,
// credentials and suspended zones are not.
func isTransient(err error) bool {
	if errors.Is(err, ErrPermanent) {
		return false
	}
	if nubulus.IsLostRace(err) {
		return true
	}
	status := nubulus.StatusOf(err)
	return status == 0 || status == http.StatusTooManyRequests || status >= 500
}
