package server

import (
	log "cblomart/go-naive-mail-forward/logger"
	"fmt"
	"net"
	"strings"
	"sync"
)

func (conn *Conn) checkRBL(hostname string) bool {
	if strings.EqualFold(hostname, Localhost) {
		// localhost cannot be bad
		return false
	}
	// check dns blacklist per ip
	bad := CheckRBLAddr(conn.conn.RemoteAddr(), conn.dnsbl)
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
	// prepare to call async
	result := false
	var wg sync.WaitGroup
	// try to resolve ips
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		// should be welcomed with a resolvable host
		return true
	}
	wg.Add(len(ips))
	for _, ip := range ips {
		go CheckRBLIPAsync(ip, rbls, &result, &wg)
	}
	wg.Wait()
	return result
}

func CheckRBLIPAsync(ip net.IP, rbls []string, res *bool, wg *sync.WaitGroup) {
	defer wg.Done()
	check := CheckRBLIP(ip, rbls)
	if !*res && check {
		*res = true
	}
}
func CheckRBLAddr(addr net.Addr, rbls []string) bool {
	tcp := addr.(*net.TCPAddr)
	return CheckRBLIP(tcp.IP, rbls)
}

func CheckRBLIP(ip net.IP, rbls []string) bool {
	log.Debugf("checking rbl on ip %s", ip.String())
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
	return result
}

func ResolvAsync(host string, res *bool, wg *sync.WaitGroup) {
	defer wg.Done()
	check := CheckA(host)
	if !*res && check {
		*res = true
	}
}
