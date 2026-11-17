package upstream

import (
	"net/url"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type schemeTestUpstream struct {
	addr string
}

func (u *schemeTestUpstream) Exchange(req *dns.Msg) (*dns.Msg, error) { return nil, nil }
func (u *schemeTestUpstream) Address() string                         { return u.addr }
func (u *schemeTestUpstream) Close() error                            { return nil }

func TestRegisterScheme(t *testing.T) {
	RegisterScheme("schemetest", func(uu *url.URL, opts *Options) (Upstream, error) {
		require.NotNil(t, opts.Logger)

		return &schemeTestUpstream{addr: uu.Host}, nil
	})

	u, err := AddressToUpstream("schemetest://example.org:853", nil)
	require.NoError(t, err)
	assert.Equal(t, "example.org:853", u.Address())

	_, err = AddressToUpstream("schemetest://bad host", nil)
	assert.Error(t, err)

	_, err = AddressToUpstream("unknowntest://example.org", nil)
	assert.Error(t, err)

	assert.Panics(t, func() {
		RegisterScheme("schemetest", func(*url.URL, *Options) (Upstream, error) { return nil, nil })
	})
	assert.Panics(t, func() {
		RegisterScheme("tls", func(*url.URL, *Options) (Upstream, error) { return nil, nil })
	})
}
