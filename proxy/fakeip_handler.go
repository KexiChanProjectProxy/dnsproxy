package proxy

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// FakeIPHandler implements BeforeRequestHandler to intercept DNS requests and
// return fake IP addresses for matching domains.
type FakeIPHandler struct {
	config    *FakeIPConfig
	allocator *FakeIPAllocator
	sourceSet netutil.SubnetSet // For fast IP matching
}

// NewFakeIPHandler creates a new FakeIP handler.
func NewFakeIPHandler(config *FakeIPConfig) *FakeIPHandler {
	return &FakeIPHandler{
		config:    config,
		allocator: NewFakeIPAllocator(config),
		sourceSet: netutil.SliceSubnetSet(config.SourceRanges),
	}
}

// HandleBefore implements BeforeRequestHandler interface.  It checks if the
// request should be handled by FakeIP and returns a response with a fake IP
// if so.
func (h *FakeIPHandler) HandleBefore(p *Proxy, dctx *DNSContext) error {
	// Check if client IP is in "from" ranges
	clientIP := dctx.Addr.Addr()
	if !h.sourceSet.Contains(clientIP) {
		return nil // Not from allowed source, skip FakeIP
	}

	// Check if we have a question
	if len(dctx.Req.Question) == 0 {
		return nil
	}

	question := dctx.Req.Question[0]
	qtype := question.Qtype

	// Only handle A and AAAA queries
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return nil
	}

	// Check if domain matches suffix patterns
	domain := strings.ToLower(question.Name)
	if !h.matchesDomainSuffix(domain) {
		return nil // Domain doesn't match, skip FakeIP
	}

	// Allocate or retrieve fake IP
	isIPv6 := qtype == dns.TypeAAAA
	fakeIP, err := h.allocator.GetOrAllocate(domain, isIPv6)
	if err != nil {
		return nil // Allocation failed, fall back to normal resolution
	}

	// Create response with fake IP
	response := h.createResponse(dctx.Req, fakeIP, qtype)

	// Return error with response to short-circuit processing
	return &BeforeRequestError{
		Err:      fmt.Errorf("fakeip: %s -> %s", domain, fakeIP),
		Response: response,
	}
}

// matchesDomainSuffix checks if domain matches any configured suffix.
func (h *FakeIPHandler) matchesDomainSuffix(domain string) bool {
	// Normalize: ensure trailing dot
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	for _, suffix := range h.config.DomainSuffixes {
		// Normalize suffix
		if !strings.HasSuffix(suffix, ".") {
			suffix += "."
		}

		// Check exact match or subdomain match
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}

	return false
}

// createResponse creates a DNS response with the fake IP.
func (h *FakeIPHandler) createResponse(req *dns.Msg, fakeIP netip.Addr, qtype uint16) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = false
	resp.RecursionAvailable = true

	// Create answer record
	var rr dns.RR

	if qtype == dns.TypeA && fakeIP.Is4() {
		rr = &dns.A{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    h.config.TTL,
			},
			A: fakeIP.AsSlice(),
		}
	} else if qtype == dns.TypeAAAA && fakeIP.Is6() {
		rr = &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    h.config.TTL,
			},
			AAAA: fakeIP.AsSlice(),
		}
	} else {
		// Type mismatch (e.g., got IPv4 but queried AAAA)
		// Return NODATA response
		resp.Rcode = dns.RcodeSuccess
		return resp
	}

	resp.Answer = []dns.RR{rr}
	return resp
}
