package upstream

import (
	"fmt"
	"net/url"
	"sync"
)

// SchemeConstructor creates an Upstream for an address whose URL scheme it was
// registered for.  uu and opts are never nil, and opts.Logger is set.
type SchemeConstructor func(uu *url.URL, opts *Options) (u Upstream, err error)

var (
	schemesMu sync.RWMutex
	schemes   = map[string]SchemeConstructor{}
)

// builtinSchemes are the URL schemes [AddressToUpstream] handles itself.
var builtinSchemes = map[string]struct{}{
	"sdns":  {},
	"udp":   {},
	"tcp":   {},
	"quic":  {},
	"tls":   {},
	"h3":    {},
	"https": {},
}

// RegisterScheme makes [AddressToUpstream] create upstreams for addresses with
// the URL scheme scheme using f.  It panics when scheme is a built-in scheme,
// is already registered, or when f is nil.  It is meant to be called from an
// init function.
func RegisterScheme(scheme string, f SchemeConstructor) {
	if f == nil {
		panic(fmt.Errorf("upstream: nil constructor for scheme %q", scheme))
	}
	if _, ok := builtinSchemes[scheme]; ok {
		panic(fmt.Errorf("upstream: scheme %q is built in", scheme))
	}

	schemesMu.Lock()
	defer schemesMu.Unlock()

	if _, ok := schemes[scheme]; ok {
		panic(fmt.Errorf("upstream: scheme %q already registered", scheme))
	}

	schemes[scheme] = f
}

// registeredScheme returns the constructor registered for scheme, if any.
func registeredScheme(scheme string) (f SchemeConstructor, ok bool) {
	schemesMu.RLock()
	defer schemesMu.RUnlock()

	f, ok = schemes[scheme]

	return f, ok
}
