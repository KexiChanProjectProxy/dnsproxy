package proxy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFakeIPHandler_HandleBefore tests the FakeIP handler with various scenarios.
func TestFakeIPHandler_HandleBefore(t *testing.T) {
	// Create test configuration
	config := &FakeIPConfig{
		Enabled: true,
		SourceRanges: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("10.0.0.0/8"),
		},
		DomainSuffixes: []string{
			"test.com",
			"example.org",
		},
		IPv4Pool: netip.MustParsePrefix("192.18.0.0/16"),
		IPv6Pool: netip.MustParsePrefix("2001:0db8:114::/48"),
		TTL:      30,
	}

	handler := NewFakeIPHandler(config)
	proxy := &Proxy{}

	t.Run("client_ip_in_source_range_matching_domain_A", func(t *testing.T) {
		// Create DNS request for A record
		req := new(dns.Msg)
		req.SetQuestion("test.com.", dns.TypeA)

		dctx := &DNSContext{
			Req:  req,
			Addr: netip.MustParseAddrPort("127.0.0.1:1234"),
		}

		err := handler.HandleBefore(proxy, dctx)

		// Should return BeforeRequestError with response
		require.Error(t, err)
		berr, ok := err.(*BeforeRequestError)
		require.True(t, ok)
		require.NotNil(t, berr.Response)

		// Verify response contains fake IP
		assert.Len(t, berr.Response.Answer, 1)
		aRecord, ok := berr.Response.Answer[0].(*dns.A)
		require.True(t, ok)
		assert.Equal(t, uint32(30), aRecord.Hdr.Ttl)

		// Verify IP is from the pool
		ip, ok := netip.AddrFromSlice(aRecord.A)
		require.True(t, ok)
		assert.True(t, config.IPv4Pool.Contains(ip))
	})

	t.Run("client_ip_in_source_range_matching_domain_AAAA", func(t *testing.T) {
		// Create DNS request for AAAA record - use different subdomain to avoid IPv4 cache
		req := new(dns.Msg)
		req.SetQuestion("ipv6.test.com.", dns.TypeAAAA)

		dctx := &DNSContext{
			Req:  req,
			Addr: netip.MustParseAddrPort("127.0.0.1:1234"),
		}

		err := handler.HandleBefore(proxy, dctx)

		// Should return BeforeRequestError with response
		require.Error(t, err)
		berr, ok := err.(*BeforeRequestError)
		require.True(t, ok)
		require.NotNil(t, berr.Response)

		// Verify response contains fake IPv6
		assert.Len(t, berr.Response.Answer, 1)
		aaaaRecord, ok := berr.Response.Answer[0].(*dns.AAAA)
		require.True(t, ok)
		assert.Equal(t, uint32(30), aaaaRecord.Hdr.Ttl)

		// Verify IP is from the pool
		ip, ok := netip.AddrFromSlice(aaaaRecord.AAAA)
		require.True(t, ok)
		assert.True(t, config.IPv6Pool.Contains(ip))
	})

	t.Run("client_ip_not_in_source_range", func(t *testing.T) {
		// Create DNS request from non-matching source IP
		req := new(dns.Msg)
		req.SetQuestion("test.com.", dns.TypeA)

		dctx := &DNSContext{
			Req:  req,
			Addr: netip.MustParseAddrPort("8.8.8.8:1234"),
		}

		err := handler.HandleBefore(proxy, dctx)

		// Should return nil (pass through)
		assert.NoError(t, err)
	})

	t.Run("domain_not_matching", func(t *testing.T) {
		// Create DNS request for non-matching domain
		req := new(dns.Msg)
		req.SetQuestion("google.com.", dns.TypeA)

		dctx := &DNSContext{
			Req:  req,
			Addr: netip.MustParseAddrPort("127.0.0.1:1234"),
		}

		err := handler.HandleBefore(proxy, dctx)

		// Should return nil (pass through)
		assert.NoError(t, err)
	})

	t.Run("subdomain_matching", func(t *testing.T) {
		// Create DNS request for subdomain
		req := new(dns.Msg)
		req.SetQuestion("sub.test.com.", dns.TypeA)

		dctx := &DNSContext{
			Req:  req,
			Addr: netip.MustParseAddrPort("127.0.0.1:1234"),
		}

		err := handler.HandleBefore(proxy, dctx)

		// Should return BeforeRequestError (subdomain matches)
		require.Error(t, err)
		berr, ok := err.(*BeforeRequestError)
		require.True(t, ok)
		require.NotNil(t, berr.Response)
	})

	t.Run("non_A_AAAA_query", func(t *testing.T) {
		// Create DNS request for MX record
		req := new(dns.Msg)
		req.SetQuestion("test.com.", dns.TypeMX)

		dctx := &DNSContext{
			Req:  req,
			Addr: netip.MustParseAddrPort("127.0.0.1:1234"),
		}

		err := handler.HandleBefore(proxy, dctx)

		// Should return nil (only handles A/AAAA)
		assert.NoError(t, err)
	})

	t.Run("same_domain_returns_same_ip", func(t *testing.T) {
		// First request
		req1 := new(dns.Msg)
		req1.SetQuestion("test.com.", dns.TypeA)

		dctx1 := &DNSContext{
			Req:  req1,
			Addr: netip.MustParseAddrPort("127.0.0.1:1234"),
		}

		err1 := handler.HandleBefore(proxy, dctx1)
		require.Error(t, err1)
		berr1, _ := err1.(*BeforeRequestError)
		aRecord1, _ := berr1.Response.Answer[0].(*dns.A)
		ip1, _ := netip.AddrFromSlice(aRecord1.A)

		// Second request for same domain
		req2 := new(dns.Msg)
		req2.SetQuestion("test.com.", dns.TypeA)

		dctx2 := &DNSContext{
			Req:  req2,
			Addr: netip.MustParseAddrPort("127.0.0.1:1234"),
		}

		err2 := handler.HandleBefore(proxy, dctx2)
		require.Error(t, err2)
		berr2, _ := err2.(*BeforeRequestError)
		aRecord2, _ := berr2.Response.Answer[0].(*dns.A)
		ip2, _ := netip.AddrFromSlice(aRecord2.A)

		// Should return same IP
		assert.Equal(t, ip1, ip2)
	})
}

// TestFakeIPAllocator tests the IP allocation logic.
func TestFakeIPAllocator(t *testing.T) {
	config := &FakeIPConfig{
		IPv4Pool: netip.MustParsePrefix("192.18.0.0/24"),
		IPv6Pool: netip.MustParsePrefix("2001:0db8:114::/64"),
		TTL:      30,
	}

	allocator := NewFakeIPAllocator(config)

	t.Run("allocate_ipv4", func(t *testing.T) {
		ip, err := allocator.GetOrAllocate("test1.com", false)
		require.NoError(t, err)
		assert.True(t, ip.Is4())
		assert.True(t, config.IPv4Pool.Contains(ip))
	})

	t.Run("allocate_ipv6", func(t *testing.T) {
		ip, err := allocator.GetOrAllocate("test2.com", true)
		require.NoError(t, err)
		assert.True(t, ip.Is6())
		assert.True(t, config.IPv6Pool.Contains(ip))
	})

	t.Run("same_domain_same_ip", func(t *testing.T) {
		ip1, err1 := allocator.GetOrAllocate("test3.com", false)
		require.NoError(t, err1)

		ip2, err2 := allocator.GetOrAllocate("test3.com", false)
		require.NoError(t, err2)

		assert.Equal(t, ip1, ip2)
	})

	t.Run("different_domains_different_ips", func(t *testing.T) {
		ip1, err1 := allocator.GetOrAllocate("test4.com", false)
		require.NoError(t, err1)

		ip2, err2 := allocator.GetOrAllocate("test5.com", false)
		require.NoError(t, err2)

		assert.NotEqual(t, ip1, ip2)
	})

	t.Run("collision_avoidance", func(t *testing.T) {
		// Allocate many IPs to test collision avoidance
		ips := make(map[netip.Addr]bool)

		for i := 0; i < 50; i++ {
			domain := "test" + string(rune('a'+i)) + ".com"
			ip, err := allocator.GetOrAllocate(domain, false)
			require.NoError(t, err)
			assert.False(t, ips[ip], "IP %s was already allocated", ip)
			ips[ip] = true
		}
	})
}

// TestFakeIPAllocator_Expiry tests the LRU expiration logic.
func TestFakeIPAllocator_Expiry(t *testing.T) {
	config := &FakeIPConfig{
		IPv4Pool: netip.MustParsePrefix("192.18.0.0/24"),
		TTL:      1, // 1 second TTL, 4 seconds expiry
	}

	allocator := NewFakeIPAllocator(config)

	// Allocate IP for domain
	ip1, err := allocator.GetOrAllocate("test.com", false)
	require.NoError(t, err)

	// Immediately query again - should get same IP
	ip2, err := allocator.GetOrAllocate("test.com", false)
	require.NoError(t, err)
	assert.Equal(t, ip1, ip2)

	// Wait for expiry (4*TTL = 4 seconds)
	time.Sleep(5 * time.Second)

	// Allocate for different domain to trigger cleanup
	_, err = allocator.GetOrAllocate("other.com", false)
	require.NoError(t, err)

	// Query original domain again - might get different IP
	ip3, err := allocator.GetOrAllocate("test.com", false)
	require.NoError(t, err)

	// Should be valid but may be different (not guaranteed due to random allocation)
	assert.True(t, config.IPv4Pool.Contains(ip3))
}

// TestFakeIPAllocator_NoPool tests error handling when no pool is configured.
func TestFakeIPAllocator_NoPool(t *testing.T) {
	config := &FakeIPConfig{
		TTL: 30,
	}

	allocator := NewFakeIPAllocator(config)

	t.Run("no_ipv4_pool", func(t *testing.T) {
		_, err := allocator.GetOrAllocate("test.com", false)
		assert.Error(t, err)
	})

	t.Run("no_ipv6_pool", func(t *testing.T) {
		_, err := allocator.GetOrAllocate("test.com", true)
		assert.Error(t, err)
	})
}

// TestFakeIPHandler_DomainMatching tests domain suffix matching logic.
func TestFakeIPHandler_DomainMatching(t *testing.T) {
	config := &FakeIPConfig{
		Enabled:        true,
		DomainSuffixes: []string{"test.com", "example.org"},
		IPv4Pool:       netip.MustParsePrefix("192.18.0.0/16"),
		TTL:            30,
	}

	handler := NewFakeIPHandler(config)

	tests := []struct {
		domain string
		want   bool
	}{
		{"test.com.", true},
		{"test.com", true},
		{"sub.test.com.", true},
		{"deep.sub.test.com.", true},
		{"nottest.com.", false},
		{"testtest.com.", false},
		{"example.org.", true},
		{"www.example.org.", true},
		{"example.com.", false},
		{"google.com.", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := handler.matchesDomainSuffix(tt.domain)
			assert.Equal(t, tt.want, got)
		})
	}
}
