package proxy

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/miekg/dns"
)

// ErrCacheRefreshInProgress is returned by [Proxy.RefreshCache] when another
// refresh, proactive or optimistic, of the same cache key is already running.
const ErrCacheRefreshInProgress errors.Error = "cache refresh already in progress"

// ErrCacheRefreshServFail is returned by [Proxy.RefreshCache] when the
// upstreams answer with SERVFAIL.  Such a response isn't cached, so that a
// refresh never replaces a usable cached answer with a failure.
const ErrCacheRefreshServFail errors.Error = "upstream answered servfail"

// ErrCacheRefreshUnavailable is returned by [Proxy.RefreshCache] when the
// general cache is disabled or can't be used for the request.
const ErrCacheRefreshUnavailable errors.Error = "cache refresh unavailable for request"

// RefreshCache resolves the request from dctx via the upstreams and stores the
// response in the general cache, bypassing the cache lookup and the shaping of
// the client response.  dctx.Req must contain exactly one question, and
// dctx.ReqECS and dctx.CustomUpstreamConfig must be nil.  dctx must not be used
// concurrently.
//
// If the cached item is still fresh and its remaining TTL is surely at least
// minRemaining, nothing is fetched, refreshed is false and ttl is the remaining
// TTL.  Since the cache keeps expiry times in whole seconds, the remaining TTL
// is only known up to a second.  If another refresh of the same key is running,
// [ErrCacheRefreshInProgress] is returned.  Otherwise, refreshed reports
// whether a response was received from an upstream, and ttl is the duration
// for which it's cached, or zero if it's not cacheable.  A SERVFAIL response
// isn't cached and [ErrCacheRefreshServFail] is returned for it.
//
// ctx is only checked before querying the upstreams, since the upstream
// exchange can't be cancelled.
func (p *Proxy) RefreshCache(
	ctx context.Context,
	dctx *DNSContext,
	minRemaining time.Duration,
) (ttl time.Duration, refreshed bool, err error) {
	if p.cache == nil ||
		p.shortFlighter == nil ||
		dctx.Req == nil ||
		len(dctx.Req.Question) != 1 ||
		dctx.ReqECS != nil ||
		dctx.CustomUpstreamConfig != nil ||
		!p.cacheWorks(dctx) {
		return 0, false, ErrCacheRefreshUnavailable
	}

	dctx.calcFlagsAndSize()

	// Request DNSSEC RRs the same way [Proxy.Resolve] does, so that the cache
	// key and the cached data match the ones of client requests.
	p.addDO(dctx.Req)

	ci, expired, key := p.cache.get(dctx.Req)
	if key == nil {
		return 0, false, ErrCacheRefreshUnavailable
	}

	if ci != nil && !expired {
		remaining := time.Duration(ci.ttl) * time.Second
		if remaining-time.Second >= minRemaining {
			return remaining, false, nil
		}
	}

	if err = ctx.Err(); err != nil {
		return 0, false, err
	}

	keyHexed := hex.EncodeToString(key)
	if _, loaded := p.shortFlighter.reqs.LoadOrStore(keyHexed, unit{}); loaded {
		return 0, false, ErrCacheRefreshInProgress
	}
	defer p.shortFlighter.reqs.Delete(keyHexed)

	refreshed, err = p.replyFromUpstream(dctx)
	if err != nil || !refreshed {
		return 0, refreshed, err
	}

	if dctx.Res.Rcode == dns.RcodeServerFailure {
		return 0, false, ErrCacheRefreshServFail
	}

	if !dctx.Res.CheckingDisabled {
		p.cacheResp(dctx)
		ttl = time.Duration(cacheTTL(dctx.Res, p.logger)) * time.Second
	}

	return ttl, true, nil
}
