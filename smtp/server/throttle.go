package server

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type throttleEntry struct {
	Name      string
	LastCheck time.Time
	Attempts  int
}

const (
	// cache for 2 hours
	throttleCacheTTL = 2 * time.Hour
	// block after tree attempts in the cache window (2 hours)
	throttleMaxAttempts = 3
)

var throttleCache []*throttleEntry
var throttleCacheLock sync.Mutex

// CheckThrottle checks the cache for the host name
func CheckThrottle(name string) bool {
	throttleCacheLock.Lock()
	defer throttleCacheLock.Unlock()
	name = strings.ToLower(strings.TrimRight(name, "."))
	attempts := 0
	toRemove := []int{}
	for i, entry := range throttleCache {
		if name == entry.Name {
			attempts = entry.Attempts
			entry.LastCheck = time.Now()
			break
		}
		if entry.LastCheck.Before(time.Now().Add(-throttleCacheTTL)) {
			toRemove = append(toRemove, i)
		}
	}
	// remove expired entries
	// sort entries to remove to avoid issues
	sort.Sort(sort.Reverse(sort.IntSlice(toRemove)))
	for _, i := range toRemove {
		// set element to remove to the last one
		throttleCache[i] = throttleCache[len(rblCache)-1]
		// remove the last element of the slice
		throttleCache = throttleCache[:len(rblCache)-1]
	}
	return attempts >= throttleMaxAttempts
}

// AddThrottle add a host to throttle list (due to bad action)
func AddThrottle(name string) {
	throttleCacheLock.Lock()
	defer throttleCacheLock.Unlock()
	// standardize name
	name = strings.ToLower(strings.TrimRight(name, "."))
	found := false
	toRemove := []int{}
	for i, entry := range throttleCache {
		if name == entry.Name {
			found = true
			entry.Attempts += 1
			entry.LastCheck = time.Now()
			break
		}
		if entry.LastCheck.Before(time.Now().Add(-throttleCacheTTL)) {
			toRemove = append(toRemove, i)
		}
	}
	// remove expired entries
	// sort entries to remove to avoid issues
	sort.Sort(sort.Reverse(sort.IntSlice(toRemove)))
	for _, i := range toRemove {
		// set element to remove to the last one
		throttleCache[i] = throttleCache[len(rblCache)-1]
		// remove the last element of the slice
		throttleCache = throttleCache[:len(rblCache)-1]
	}
	if !found {
		throttleCache = append(throttleCache, &throttleEntry{Name: name, Attempts: 1, LastCheck: time.Now()})
	}
}
