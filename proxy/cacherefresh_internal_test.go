package proxy

import (
	"context"
	"encoding/hex"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingUpstream is an [upstream.Upstream] that counts exchanges and answers
// with a single A record with the configured TTL, or with SERVFAIL.
type countingUpstream struct {
	calls    atomic.Int32
	servFail atomic.Bool
	ttl      uint32
}

// type check
var _ upstream.Upstream = (*countingUpstream)(nil)

// Exchange implements the [upstream.Upstream] interface for *countingUpstream.
func (u *countingUpstream) Exchange(m *dns.Msg) (resp *dns.Msg, err error) {
	u.calls.Add(1)

	resp = (&dns.Msg{}).SetReply(m)
	if u.servFail.Load() {
		resp.Rcode = dns.RcodeServerFailure

		return resp, nil
	}

	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{
			Name:   m.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    u.ttl,
		},
		A: net.IP{1, 2, 3, 4},
	}}

	return resp, nil
}

// Address implements the [upstream.Upstream] interface for *countingUpstream.
func (u *countingUpstream) Address() (addr string) { return "counting" }

// Close implements the [upstream.Upstream] interface for *countingUpstream.
func (u *countingUpstream) Close() (err error) { return nil }

func TestProxy_RefreshCache(t *testing.T) {
	ups := &countingUpstream{ttl: 60}
	p := mustNew(t, &Config{
		Logger:          testLogger,
		UpstreamConfig:  &UpstreamConfig{Upstreams: []upstream.Upstream{ups}},
		TrustedProxies:  defaultTrustedProxies,
		CacheEnabled:    true,
		CacheOptimistic: true,
	})

	ctx := context.Background()
	newDCtx := func() (d *DNSContext) {
		return &DNSContext{Proto: ProtoUDP, Req: newHostTestMessage("refresh")}
	}

	ttl, refreshed, err := p.RefreshCache(ctx, newDCtx(), 0)
	require.NoError(t, err)
	assert.True(t, refreshed)
	assert.Equal(t, 60*time.Second, ttl)
	assert.Equal(t, int32(1), ups.calls.Load())

	// The item is cached and is fresh enough.
	ttl, refreshed, err = p.RefreshCache(ctx, newDCtx(), 10*time.Second)
	require.NoError(t, err)
	assert.False(t, refreshed)
	assert.InDelta(t, 60*time.Second, ttl, float64(2*time.Second))
	assert.Equal(t, int32(1), ups.calls.Load())

	// The remaining TTL is only known up to a second.
	_, refreshed, err = p.RefreshCache(ctx, newDCtx(), 60*time.Second)
	require.NoError(t, err)
	assert.True(t, refreshed)
	assert.Equal(t, int32(2), ups.calls.Load())

	// The cached item is cached but should be refreshed in advance.
	ttl, refreshed, err = p.RefreshCache(ctx, newDCtx(), 2*time.Minute)
	require.NoError(t, err)
	assert.True(t, refreshed)
	assert.Equal(t, 60*time.Second, ttl)
	assert.Equal(t, int32(3), ups.calls.Load())

	// The cache refreshed by RefreshCache is used by client requests.
	d := newDCtx()
	require.NoError(t, p.Resolve(ctx, d))
	require.NotNil(t, d.Res)
	assert.Equal(t, int32(3), ups.calls.Load())

	// SERVFAIL doesn't replace the cached answer.
	ups.servFail.Store(true)
	_, refreshed, err = p.RefreshCache(ctx, newDCtx(), time.Hour)
	assert.ErrorIs(t, err, ErrCacheRefreshServFail)
	assert.False(t, refreshed)
	assert.Equal(t, int32(4), ups.calls.Load())

	ups.servFail.Store(false)
	d = newDCtx()
	require.NoError(t, p.Resolve(ctx, d))
	require.Len(t, d.Res.Answer, 1)
	assert.Equal(t, int32(4), ups.calls.Load())

	// A cancelled context prevents querying the upstreams.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, _, err = p.RefreshCache(cancelled, newDCtx(), time.Hour)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int32(4), ups.calls.Load())

	// Another refresh of the same key is in progress.
	d = newDCtx()
	p.addDO(d.Req)
	_, _, key := p.cache.get(d.Req)
	require.NotNil(t, key)

	p.shortFlighter.reqs.Store(hex.EncodeToString(key), unit{})
	_, _, err = p.RefreshCache(ctx, newDCtx(), time.Hour)
	assert.ErrorIs(t, err, ErrCacheRefreshInProgress)
	assert.Equal(t, int32(4), ups.calls.Load())
}

func TestProxy_RefreshCache_unavailable(t *testing.T) {
	ups := &countingUpstream{ttl: 60}
	p := mustNew(t, &Config{
		Logger:         testLogger,
		UpstreamConfig: &UpstreamConfig{Upstreams: []upstream.Upstream{ups}},
		TrustedProxies: defaultTrustedProxies,
	})

	_, _, err := p.RefreshCache(
		context.Background(),
		&DNSContext{Proto: ProtoUDP, Req: newHostTestMessage("refresh")},
		0,
	)
	assert.ErrorIs(t, err, ErrCacheRefreshUnavailable)
	assert.Zero(t, ups.calls.Load())
}

// TestProxy_RefreshCache_parallelSingleUpstream checks that, by design, a
// proactive refresh queries only one upstream in the parallel mode, while a
// client request still queries all of them.
func TestProxy_RefreshCache_parallelSingleUpstream(t *testing.T) {
	first, second := &countingUpstream{ttl: 60}, &countingUpstream{ttl: 60}
	p := mustNew(t, &Config{
		Logger: testLogger,
		UpstreamConfig: &UpstreamConfig{
			Upstreams: []upstream.Upstream{first, second},
		},
		UpstreamMode:   UpstreamModeParallel,
		TrustedProxies: defaultTrustedProxies,
		CacheEnabled:   true,
	})

	calls := func() (n int32) { return first.calls.Load() + second.calls.Load() }

	_, refreshed, err := p.RefreshCache(
		context.Background(),
		&DNSContext{Proto: ProtoUDP, Req: newHostTestMessage("refresh")},
		0,
	)
	require.NoError(t, err)
	assert.True(t, refreshed)
	assert.Equal(t, int32(1), calls())
}
