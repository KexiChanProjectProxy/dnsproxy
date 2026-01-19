package proxy

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net/netip"
	"sync"
	"time"
)

// fakeIPMapping tracks a domain→IP assignment with LRU expiration.
type fakeIPMapping struct {
	ip         netip.Addr
	lastAccess time.Time // Last query time for LRU expiration
}

// FakeIPAllocator manages fake IP allocation with random selection and
// collision avoidance.
type FakeIPAllocator struct {
	mu sync.RWMutex

	// Configuration
	ipv4Pool   netip.Prefix
	ipv6Pool   netip.Prefix
	ttl        time.Duration // 30 seconds
	expiryTime time.Duration // 120 seconds (4*TTL)

	// State
	domainMap map[string]*fakeIPMapping // domain → IP mapping
	usedIPs   map[netip.Addr]string     // IP → domain (for collision check)
}

// NewFakeIPAllocator creates a new FakeIP allocator.
func NewFakeIPAllocator(config *FakeIPConfig) *FakeIPAllocator {
	return &FakeIPAllocator{
		ipv4Pool:   config.IPv4Pool,
		ipv6Pool:   config.IPv6Pool,
		ttl:        time.Duration(config.TTL) * time.Second,
		expiryTime: time.Duration(config.TTL) * 4 * time.Second, // 4*TTL
		domainMap:  make(map[string]*fakeIPMapping),
		usedIPs:    make(map[netip.Addr]string),
	}
}

// GetOrAllocate returns a fake IP for the given domain.  If the domain already
// has a mapping within the expiry window, it returns that IP and refreshes the
// access time.  Otherwise, it allocates a new random IP from the pool.
func (a *FakeIPAllocator) GetOrAllocate(domain string, isIPv6 bool) (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Clean expired entries first
	a.cleanExpiredLocked()

	// Check if we already have a mapping
	if mapping, exists := a.domainMap[domain]; exists {
		// Refresh last access time
		mapping.lastAccess = time.Now()
		return mapping.ip, nil
	}

	// Allocate new IP
	var ip netip.Addr
	var err error

	if isIPv6 && a.ipv6Pool.IsValid() {
		ip, err = a.allocateRandomIP(a.ipv6Pool)
	} else if a.ipv4Pool.IsValid() {
		ip, err = a.allocateRandomIP(a.ipv4Pool)
	} else {
		return netip.Addr{}, fmt.Errorf("no suitable IP pool configured")
	}

	if err != nil {
		return netip.Addr{}, err
	}

	// Store mapping
	mapping := &fakeIPMapping{
		ip:         ip,
		lastAccess: time.Now(),
	}
	a.domainMap[domain] = mapping
	a.usedIPs[ip] = domain

	return ip, nil
}

// allocateRandomIP allocates a random IP from the pool, avoiding already used
// IPs.  It makes up to 100 attempts to find an unused IP.
func (a *FakeIPAllocator) allocateRandomIP(pool netip.Prefix) (netip.Addr, error) {
	// Calculate pool size
	bits := pool.Bits()
	totalBits := 32
	if pool.Addr().Is6() {
		totalBits = 128
	}
	availableBits := totalBits - bits

	// Safety check: cap at ~1M IPs to prevent huge allocation
	if availableBits > 20 {
		availableBits = 20
	}

	poolSize := 1 << availableBits
	maxAttempts := 100 // Prevent infinite loop

	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Generate random offset
		offset, err := rand.Int(rand.Reader, big.NewInt(int64(poolSize)))
		if err != nil {
			return netip.Addr{}, err
		}

		// Calculate IP address
		ip := addToPrefix(pool, offset.Uint64())

		// Check if already in use
		if _, used := a.usedIPs[ip]; !used {
			return ip, nil
		}
	}

	return netip.Addr{}, fmt.Errorf("failed to allocate IP after %d attempts", maxAttempts)
}

// addToPrefix adds an offset to the prefix base address.
func addToPrefix(prefix netip.Prefix, offset uint64) netip.Addr {
	addr := prefix.Addr()

	if addr.Is4() {
		ipInt := binary.BigEndian.Uint32(addr.AsSlice())
		ipInt += uint32(offset)
		ipBytes := [4]byte{}
		binary.BigEndian.PutUint32(ipBytes[:], ipInt)
		result, _ := netip.AddrFromSlice(ipBytes[:])
		return result
	}

	// IPv6: add offset to last 64 bits
	ipBytes := addr.As16()
	low := binary.BigEndian.Uint64(ipBytes[8:])
	low += offset
	binary.BigEndian.PutUint64(ipBytes[8:], low)
	result, _ := netip.AddrFromSlice(ipBytes[:])
	return result
}

// cleanExpiredLocked removes domain→IP mappings that haven't been queried for
// 4*TTL seconds.  Must be called with the mutex locked.
func (a *FakeIPAllocator) cleanExpiredLocked() {
	now := time.Now()
	cutoff := now.Add(-a.expiryTime)

	for domain, mapping := range a.domainMap {
		if mapping.lastAccess.Before(cutoff) {
			delete(a.domainMap, domain)
			delete(a.usedIPs, mapping.ip)
		}
	}
}
