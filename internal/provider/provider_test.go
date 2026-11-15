package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
	nubulus "github.com/nubulus-network/nubulus-go"

	"github.com/nubulus-network/external-dns-webhook/internal/webhook"
)

// fakeDNS is dns-api in memory, faithful in the one place that matters: every
// value is parsed with miekg exactly as dns-api does before the UPDATE, and
// read back the way its AXFR adapter renders it. The round trip the tests
// check is therefore the one the primary performs.
type fakeDNS struct {
	mu     sync.Mutex
	zones  []nubulus.Zone
	rrsets map[string]map[string]nubulus.RRset // zone → name/type → set
	puts   int
	dels   int
	failOn string // "name/type" whose writes fail
	failAs error
}

func newFake(zones ...string) *fakeDNS {
	f := &fakeDNS{rrsets: map[string]map[string]nubulus.RRset{}}
	for _, z := range zones {
		status := "active"
		if strings.HasPrefix(z, "!") {
			z, status = z[1:], "pending_verification"
		}
		f.zones = append(f.zones, nubulus.Zone{Name: z, Status: status})
		f.rrsets[z] = map[string]nubulus.RRset{
			z + "./SOA": {Name: z + ".", Type: "SOA", TTL: 3600, Values: []string{"ns1.example.net. hostmaster.example.net. 1 3600 600 86400 300"}},
			z + "./NS":  {Name: z + ".", Type: "NS", TTL: 3600, Values: []string{"ns1.example.net.", "ns2.example.net."}},
		}
	}
	return f
}

func (f *fakeDNS) ListZones(context.Context) ([]nubulus.Zone, error) {
	return append([]nubulus.Zone(nil), f.zones...), nil
}

func (f *fakeDNS) ZoneContent(_ context.Context, zone string) (*nubulus.ZoneContent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := &nubulus.ZoneContent{Zone: zone}
	for _, s := range f.rrsets[zone] {
		c.RRsets = append(c.RRsets, s)
	}
	return c, nil
}

func (f *fakeDNS) PutRRset(_ context.Context, zone, name, rrtype string, ttl uint32, values []string) (*nubulus.RRset, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn == name+"/"+rrtype {
		return nil, f.failAs
	}
	if !strings.HasSuffix(name, ".") {
		return nil, fmt.Errorf("name %q is not fully qualified", name)
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		// dns-api: recordsOf → dns.NewRR. AXFR: rr.String() minus the header.
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", name, ttl, rrtype, v))
		if err != nil || rr == nil {
			return nil, &nubulus.APIError{Status: http.StatusBadRequest, Code: "INVALID_RDATA", Message: v}
		}
		out = append(out, strings.TrimPrefix(rr.String(), rr.Header().String()))
	}
	sort.Strings(out)
	set := nubulus.RRset{Name: name, Type: rrtype, TTL: ttl, Values: out}
	f.rrsets[zone][name+"/"+rrtype] = set
	f.puts++
	return &set, nil
}

func (f *fakeDNS) DeleteRRset(_ context.Context, zone, name, rrtype string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn == name+"/"+rrtype {
		return f.failAs
	}
	key := name + "/" + rrtype
	if _, ok := f.rrsets[zone][key]; !ok {
		return &nubulus.APIError{Status: http.StatusNotFound, Code: "RRSET_NOT_FOUND"}
	}
	delete(f.rrsets[zone], key)
	f.dels++
	return nil
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// converge runs what one external-dns cycle does with desired endpoints and
// returns the plan it would compute against the current records: endpoints to
// create, to update and to delete, compared as strings.
func plan(t *testing.T, p *Provider, desired []*webhook.Endpoint) (create, update, del []string) {
	t.Helper()
	ctx := context.Background()
	adj, err := p.AdjustEndpoints(ctx, desired)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := p.Records(ctx)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]*webhook.Endpoint{}
	for _, e := range cur {
		have[e.DNSName+"/"+e.RecordType] = e
	}
	want := map[string]bool{}
	for _, e := range adj {
		key := e.DNSName + "/" + e.RecordType
		want[key] = true
		h, ok := have[key]
		switch {
		case !ok:
			create = append(create, key)
		case h.RecordTTL != e.RecordTTL || !reflect.DeepEqual(h.Targets, e.Targets):
			update = append(update, fmt.Sprintf("%s %v/%d → %v/%d", key, h.Targets, h.RecordTTL, e.Targets, e.RecordTTL))
		}
	}
	for key := range have {
		if !want[key] {
			del = append(del, key)
		}
	}
	return
}

// TestSecondCycleIsQuiet is the reason this package has tests: after writing
// what external-dns wants, reading it back must produce exactly what
// adjustendpoints produced, or external-dns rewrites the record every minute.
func TestSecondCycleIsQuiet(t *testing.T) {
	long := strings.Repeat("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", 8)
	desired := []*webhook.Endpoint{
		{DNSName: "www.example.com", RecordType: "A", Targets: []string{"203.0.113.11", "203.0.113.10"}},
		{DNSName: "WWW.example.com.", RecordType: "AAAA", Targets: []string{"2001:DB8:0:0::1"}, RecordTTL: 120},
		{DNSName: "app.example.com", RecordType: "CNAME", Targets: []string{"lb.Example.net"}, RecordTTL: 30},
		{DNSName: "mail.example.com", RecordType: "MX", Targets: []string{"10 mx1.example.com", "20 mx2.example.com."}},
		{DNSName: "_sip._tcp.example.com", RecordType: "SRV", Targets: []string{"10 5 5060 sip.example.com"}},
		{DNSName: "example.com", RecordType: "CAA", Targets: []string{`0 issue "letsencrypt.org"`}},
		// The ownership record, quoted as the TXT registry writes it…
		{DNSName: "a-www.example.com", RecordType: "TXT", Targets: []string{`"heritage=external-dns,external-dns/owner=k8s,external-dns/resource=ingress/default/web"`}},
		// …and unquoted, which other versions and users write.
		{DNSName: "app.example.com.sub.example.com", RecordType: "TXT", Targets: []string{`heritage=external-dns,external-dns/owner=k8s`}},
		// Longer than one character-string: the primary splits it.
		{DNSName: "sel._domainkey.example.com", RecordType: "TXT", Targets: []string{long}},
		// Characters the presentation format escapes.
		{DNSName: "odd.example.com", RecordType: "TXT", Targets: []string{`say "hi" \ bye; ñ`}},
		// A zone below another zone.
		{DNSName: "x.k8s.example.com", RecordType: "A", Targets: []string{"192.0.2.1"}, RecordTTL: 999999},
	}

	f := newFake("example.com", "k8s.example.com")
	p := New(f, quietLogger())
	ctx := context.Background()

	adj, err := p.AdjustEndpoints(ctx, desired)
	if err != nil {
		t.Fatal(err)
	}
	if len(adj) != len(desired) {
		t.Fatalf("adjust kept %d of %d endpoints", len(adj), len(desired))
	}
	if err := p.ApplyChanges(ctx, &webhook.Changes{Create: adj}); err != nil {
		t.Fatal(err)
	}

	create, update, del := plan(t, p, desired)
	if len(create)+len(update)+len(del) != 0 {
		t.Fatalf("second cycle is not quiet:\ncreate %v\nupdate %v\ndelete %v", create, update, del)
	}

	if _, ok := f.rrsets["k8s.example.com"]["x.k8s.example.com./A"]; !ok {
		t.Error("x.k8s.example.com went to the parent zone instead of k8s.example.com")
	}
	if got := f.rrsets["example.com"]["sel._domainkey.example.com./TXT"].Values[0]; !strings.Contains(got, `" "`) {
		t.Errorf("long TXT was not split into strings: %s", got)
	}
}

func TestRecordsHidesPlatformRecords(t *testing.T) {
	f := newFake("example.com", "!pending.org")
	f.rrsets["example.com"]["sub.example.com./NS"] = nubulus.RRset{Name: "sub.example.com.", Type: "NS", TTL: 300, Values: []string{"ns.other.net."}}
	f.rrsets["pending.org"]["www.pending.org./A"] = nubulus.RRset{Name: "www.pending.org.", Type: "A", TTL: 300, Values: []string{"192.0.2.1"}}

	eps, err := New(f, quietLogger()).Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].DNSName != "sub.example.com" || eps[0].Targets[0] != "ns.other.net" {
		t.Fatalf("want only the delegation of sub.example.com, got %+v", eps)
	}
}

func TestAdjustDropsWhatCannotBeWritten(t *testing.T) {
	p := New(newFake("example.com", "!pending.org"), quietLogger())
	in := []*webhook.Endpoint{
		{DNSName: "w.example.com", RecordType: "A", Targets: []string{"192.0.2.1"}, SetIdentifier: "eu"},
		{DNSName: "example.com", RecordType: "CNAME", Targets: []string{"x.net"}},
		{DNSName: "example.com", RecordType: "NS", Targets: []string{"ns.x.net"}},
		{DNSName: "example.com", RecordType: "SOA", Targets: []string{"x"}},
		{DNSName: "www.pending.org", RecordType: "A", Targets: []string{"192.0.2.1"}},
		{DNSName: "www.other.net", RecordType: "A", Targets: []string{"192.0.2.1"}},
		{DNSName: "ok.example.com", RecordType: "A", Targets: []string{"192.0.2.1"}},
	}
	out, err := p.AdjustEndpoints(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].DNSName != "ok.example.com" || out[0].RecordTTL != DefaultTTL {
		t.Fatalf("want only ok.example.com with the default TTL, got %+v", out)
	}
}

func TestApplyDeletesFirst(t *testing.T) {
	f := newFake("example.com")
	f.rrsets["example.com"]["app.example.com./A"] = nubulus.RRset{Name: "app.example.com.", Type: "A", TTL: 300, Values: []string{"192.0.2.1"}}
	p := New(f, quietLogger())

	// A → CNAME on the same name. The fake does not enforce the coexistence
	// rule, so the order is checked through the final state and the counts.
	err := p.ApplyChanges(context.Background(), &webhook.Changes{
		Create: []*webhook.Endpoint{{DNSName: "app.example.com", RecordType: "CNAME", Targets: []string{"lb.example.net"}, RecordTTL: 300}},
		Delete: []*webhook.Endpoint{
			{DNSName: "app.example.com", RecordType: "A", Targets: []string{"192.0.2.1"}},
			{DNSName: "gone.example.com", RecordType: "A", Targets: []string{"192.0.2.9"}}, // 404 is success
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.rrsets["example.com"]["app.example.com./A"]; ok {
		t.Error("A was not deleted")
	}
	if got := f.rrsets["example.com"]["app.example.com./CNAME"].Values; len(got) != 1 || got[0] != "lb.example.net." {
		t.Errorf("CNAME = %v", got)
	}
}

func TestApplyClassifiesFailures(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		permanent bool
	}{
		{"validation", &nubulus.APIError{Status: 400, Code: "INVALID_RDATA"}, true},
		{"suspended zone", &nubulus.APIError{Status: 409, Code: "ZONE_NOT_ACTIVE"}, true},
		{"lost race twice", &nubulus.APIError{Status: 409, Code: nubulus.CodePreconditionFailed}, false},
		{"primary down", &nubulus.APIError{Status: 502}, false},
		{"rate limited", &nubulus.APIError{Status: 429}, false},
		{"network", errors.New("dial tcp: connection refused"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake("example.com")
			f.failOn, f.failAs = "bad.example.com./A", tc.err
			p := New(f, quietLogger())
			err := p.ApplyChanges(context.Background(), &webhook.Changes{Create: []*webhook.Endpoint{
				{DNSName: "bad.example.com", RecordType: "A", Targets: []string{"192.0.2.1"}},
				{DNSName: "good.example.com", RecordType: "A", Targets: []string{"192.0.2.2"}},
			}})
			if err == nil {
				t.Fatal("want an error")
			}
			if got := errors.Is(err, ErrPermanent); got != tc.permanent {
				t.Errorf("permanent = %v, want %v (%v)", got, tc.permanent, err)
			}
			if f.puts != 1 {
				t.Errorf("one failure must not stop the rest of the batch: %d writes", f.puts)
			}
		})
	}
}
