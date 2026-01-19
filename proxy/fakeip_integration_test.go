package proxy_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFakeIPIntegration tests FakeIP functionality end-to-end.
func TestFakeIPIntegration(t *testing.T) {
	// Create upstream config
	upstreamAddr := "8.8.8.8:53"
	opts := &upstream.Options{
		Timeout: 3 * time.Second,
	}

	u, err := upstream.AddressToUpstream(upstreamAddr, opts)
	require.NoError(t, err)

	upstreamConfig := &proxy.UpstreamConfig{
		Upstreams: []upstream.Upstream{u},
	}

	// Create FakeIP config
	fakeIPConfig := &proxy.FakeIPConfig{
		Enabled: true,
		SourceRanges: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
		},
		DomainSuffixes: []string{
			"fakeip.test",
			"example.test",
		},
		IPv4Pool: netip.MustParsePrefix("192.18.0.0/16"),
		IPv6Pool: netip.MustParsePrefix("2001:0db8:114::/48"),
		TTL:      30,
	}

	// Create proxy configuration
	proxyConfig := &proxy.Config{
		UDPListenAddr: []*net.UDPAddr{
			{IP: net.IPv4(127, 0, 0, 1), Port: 0},
		},
		UpstreamConfig:       upstreamConfig,
		FakeIPConfig:         fakeIPConfig,
		BeforeRequestHandler: proxy.NewFakeIPHandler(fakeIPConfig),
	}

	// Create and start proxy
	p, err := proxy.New(proxyConfig)
	require.NoError(t, err)

	ctx := context.Background()
	err = p.Start(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Shutdown(ctx) })

	// Get the actual listen address
	addr := p.Addrs(proxy.ProtoUDP)[0].String()

	t.Run("fakeip_domain_returns_fake_ip_v4", func(t *testing.T) {
		// Create DNS query for A record
		req := new(dns.Msg)
		req.SetQuestion("test.fakeip.test.", dns.TypeA)

		// Send query
		client := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(req, addr)

		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, resp.Answer, 1)

		// Verify it's an A record
		aRecord, ok := resp.Answer[0].(*dns.A)
		require.True(t, ok)

		// Verify TTL is 30
		assert.Equal(t, uint32(30), aRecord.Hdr.Ttl)

		// Verify IP is from fake pool
		ip, ok := netip.AddrFromSlice(aRecord.A)
		require.True(t, ok)
		assert.True(t, fakeIPConfig.IPv4Pool.Contains(ip))
	})

	t.Run("fakeip_domain_returns_fake_ip_v6", func(t *testing.T) {
		// Create DNS query for AAAA record
		req := new(dns.Msg)
		req.SetQuestion("test-v6.fakeip.test.", dns.TypeAAAA)

		// Send query
		client := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(req, addr)

		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, resp.Answer, 1)

		// Verify it's an AAAA record
		aaaaRecord, ok := resp.Answer[0].(*dns.AAAA)
		require.True(t, ok)

		// Verify TTL is 30
		assert.Equal(t, uint32(30), aaaaRecord.Hdr.Ttl)

		// Verify IP is from fake pool
		ip, ok := netip.AddrFromSlice(aaaaRecord.AAAA)
		require.True(t, ok)
		assert.True(t, fakeIPConfig.IPv6Pool.Contains(ip))
	})

	t.Run("non_fakeip_domain_uses_upstream", func(t *testing.T) {
		// Create DNS query for a real domain
		req := new(dns.Msg)
		req.SetQuestion("google.com.", dns.TypeA)

		// Send query
		client := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(req, addr)

		require.NoError(t, err)
		require.NotNil(t, resp)

		// Should get a response from upstream (might have answers or not depending on network)
		// The key is that it doesn't return a fake IP from our pool
		for _, ans := range resp.Answer {
			if aRecord, ok := ans.(*dns.A); ok {
				ip, ok := netip.AddrFromSlice(aRecord.A)
				require.True(t, ok)
				// Should NOT be from our fake pool
				assert.False(t, fakeIPConfig.IPv4Pool.Contains(ip))
			}
		}
	})

	t.Run("same_domain_returns_same_fake_ip", func(t *testing.T) {
		// First query
		req1 := new(dns.Msg)
		req1.SetQuestion("consistent.fakeip.test.", dns.TypeA)

		client := &dns.Client{Timeout: 3 * time.Second}
		resp1, _, err := client.Exchange(req1, addr)

		require.NoError(t, err)
		require.NotNil(t, resp1)
		require.Len(t, resp1.Answer, 1)

		aRecord1, ok := resp1.Answer[0].(*dns.A)
		require.True(t, ok)
		ip1, _ := netip.AddrFromSlice(aRecord1.A)

		// Second query for the same domain
		req2 := new(dns.Msg)
		req2.SetQuestion("consistent.fakeip.test.", dns.TypeA)

		resp2, _, err := client.Exchange(req2, addr)

		require.NoError(t, err)
		require.NotNil(t, resp2)
		require.Len(t, resp2.Answer, 1)

		aRecord2, ok := resp2.Answer[0].(*dns.A)
		require.True(t, ok)
		ip2, _ := netip.AddrFromSlice(aRecord2.A)

		// Should be the same IP
		assert.Equal(t, ip1, ip2)
	})

	t.Run("subdomain_matching", func(t *testing.T) {
		// Query for subdomain
		req := new(dns.Msg)
		req.SetQuestion("sub.domain.fakeip.test.", dns.TypeA)

		client := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(req, addr)

		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Len(t, resp.Answer, 1)

		// Should get a fake IP
		aRecord, ok := resp.Answer[0].(*dns.A)
		require.True(t, ok)

		ip, ok := netip.AddrFromSlice(aRecord.A)
		require.True(t, ok)
		assert.True(t, fakeIPConfig.IPv4Pool.Contains(ip))
	})
}

// ptr returns a pointer to the given addrport.
func ptr(a netip.AddrPort) *netip.AddrPort {
	return &a
}
