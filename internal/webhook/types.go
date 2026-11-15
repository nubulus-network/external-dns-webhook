// Package webhook implements the HTTP side of the external-dns webhook
// provider protocol. The wire types are declared here instead of importing
// sigs.k8s.io/external-dns: that module drags in the whole Kubernetes client,
// and the protocol is four routes and three small JSON shapes.
package webhook

// MediaType is the only media type the protocol defines. The version travels
// as a parameter of it, not in a header of its own.
const MediaType = "application/external.dns.webhook+json;version=1"

// Endpoint mirrors endpoint.Endpoint in external-dns, field tags included.
type Endpoint struct {
	DNSName          string             `json:"dnsName,omitempty"`
	Targets          []string           `json:"targets,omitempty"`
	RecordType       string             `json:"recordType,omitempty"`
	SetIdentifier    string             `json:"setIdentifier,omitempty"`
	RecordTTL        int64              `json:"recordTTL,omitempty"`
	Labels           map[string]string  `json:"labels,omitempty"`
	ProviderSpecific []ProviderSpecific `json:"providerSpecific,omitempty"`
}

// ProviderSpecific mirrors endpoint.ProviderSpecificProperty.
type ProviderSpecific struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

// Changes mirrors plan.Changes.
type Changes struct {
	Create    []*Endpoint `json:"create,omitempty"`
	UpdateOld []*Endpoint `json:"updateOld,omitempty"`
	UpdateNew []*Endpoint `json:"updateNew,omitempty"`
	Delete    []*Endpoint `json:"delete,omitempty"`
}

// DomainFilter is what GET / answers.
//
// Include is the key endpoint.DomainFilter reads today. Filters is the one the
// OpenAPI document of the protocol (v0.15) still shows. Unknown keys are
// ignored when decoding, so sending both works with either side.
type DomainFilter struct {
	Include []string `json:"include,omitempty"`
	Filters []string `json:"filters,omitempty"`
}
