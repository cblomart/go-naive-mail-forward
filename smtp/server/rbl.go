package server

import (
	log "cblomart/go-naive-mail-forward/logger"
	"cblomart/go-naive-mail-forward/smtp/dns"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type rblEntry struct {
	Name      string
	LastCheck time.Time
	Bad       bool
}

const rblCacheTTL = 2 * time.Hour

var rblCache []*rblEntry
var rblCacheLock sync.Mutex

func checkRBLCache(name string) (bool, bool) {
	rblCacheLock.Lock()
	defer rblCacheLock.Unlock()
	// standardize name
	name = strings.ToLower(strings.TrimRight(name, "."))
	// default return values
	bad := true
	found := false
	toRemove := []int{}
	for i, entry := range rblCache {
		if name == entry.Name {
			found = true
			bad = entry.Bad
			entry.LastCheck = time.Now()
			break
		}
		if entry.LastCheck.Before(time.Now().Add(-rblCacheTTL)) {
			toRemove = append(toRemove, i)
		}
	}
	// remove expired entries
	// sort entries to remove to avoid issues
	sort.Sort(sort.Reverse(sort.IntSlice(toRemove)))
	for _, i := range toRemove {
		// set element to remove to the last one
		rblCache[i] = rblCache[len(rblCache)-1]
		// remove the last element of the slice
		rblCache = rblCache[:len(rblCache)-1]
	}
	// return result
	return bad, found
}

func addRBLCache(name string, bad bool) {
	rblCacheLock.Lock()
	defer rblCacheLock.Unlock()
	// standardize name
	name = strings.ToLower(strings.TrimRight(name, "."))
	rblCache = append(rblCache, &rblEntry{Name: name, Bad: bad, LastCheck: time.Now()})
}

func (conn *Conn) checkRBL(hostname string) bool {
	if strings.EqualFold(hostname, Localhost) {
		// localhost cannot be bad
		return false
	}
	// check dns blacklist per ip
	tcpAddr := conn.conn.RemoteAddr().(*net.TCPAddr)
	bad := CheckRBLIP(tcpAddr.IP, conn.dnsbl)
	if !bad {
		// check dns blacklist per name
		bad = CheckRBLName(hostname, conn.dnsbl)
	}
	return bad
}

func CheckRBLName(host string, rbls []string) bool {
	log.Debugf("checking rbl on hostname %s", host)
	if !DomainMatch.MatchString(host) {
		// do not try to match on non hostname
		return true
	}
	// check in the cache
	bad, found := checkRBLCache(host)
	if found {
		return bad
	}
	// prepare to call async
	result := false
	var wg sync.WaitGroup
	// try to resolve ips
	ips, err := dns.LookupIP(host)
	if err != nil || len(ips) == 0 {
		// should be welcomed with a resolvable host
		return true
	}
	wg.Add(len(ips))
	for _, ip := range ips {
		go CheckRBLIPAsync(ip, rbls, &result, &wg)
	}
	wg.Wait()
	addRBLCache(host, result)
	return result
}

func CheckRBLIPAsync(ip net.IP, rbls []string, res *bool, wg *sync.WaitGroup) {
	defer wg.Done()
	check := CheckRBLIP(ip, rbls)
	if !*res && check {
		*res = true
	}
}

func CheckRBLIP(ip net.IP, rbls []string) bool {
	log.Debugf("checking rbl on ip %s", ip.String())
	// check in cache
	bad, found := checkRBLCache(ip.String())
	if found {
		return bad
	}
	// calculate prefix to resolve
	prefix := ""
	tmp := ip.String()
	if strings.Contains(tmp, ":") {
		// ipv6
		var sb strings.Builder
		ip6 := ExpandIp6(tmp)
		for i := len(ip6) - 1; i >= 0; i-- {
			sb.WriteByte(ip6[i])
			if i > 0 {
				sb.WriteRune('.')
			}
		}
		prefix = sb.String()

	} else {
		// ipv4
		prefix = strings.Join(Reverse(strings.Split(tmp, ".")), ".")
	}
	// prefix should be there
	if len(prefix) == 0 {
		log.Warnf("RBL unable go get dns prefix for %s", ip.String())
		return false
	}
	// check in // for ip resolution result (true: found; false: not found)
	var wg sync.WaitGroup
	wg.Add(len(rbls))
	var result bool
	for _, rbl := range rbls {
		go ResolvAsync(fmt.Sprintf("%s.%s", prefix, rbl), &result, &wg)
	}
	wg.Wait()
	addRBLCache(ip.String(), result)
	return result
}

func ResolvAsync(host string, res *bool, wg *sync.WaitGroup) {
	defer wg.Done()
	check := CheckA(host)
	if !*res && check {
		*res = true
	}
}
