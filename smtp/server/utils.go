package server

import (
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"

	log "cblomart/go-naive-mail-forward/logger"
)

func CheckA(host string) bool {
	ars, err := net.LookupIP(host)
	return err == nil && len(ars) > 0
}

func ExpandIp6(shortip6 string) string {
	if strings.Contains(shortip6, "::") {
		ip6s := 0
		for _, c := range shortip6 {
			if c == ':' {
				ip6s++
			}
		}
		cnt := 7 - ip6s
		replace := strings.Repeat(":", cnt+2)
		shortip6 = strings.ReplaceAll(shortip6, "::", replace)
	}
	ip6parts := strings.Split(shortip6, ":")
	var sb strings.Builder
	for i := range ip6parts {
		for {
			if len(ip6parts[i]) == 4 {
				break
			}
			ip6parts[i] = "0" + ip6parts[i]
		}
		sb.WriteString(ip6parts[i])
	}
	return sb.String()
}

func IsAsciiPrintable(text string) bool {
	for _, c := range text {
		if c < 32 && c > 126 {
			return false
		}
	}
	return true
}

func Reverse(slice []string) []string {
	if len(slice) <= 1 {
		return slice
	}
	for i := 0; i < len(slice)/2; i++ {
		tmp := slice[i]
		slice[i] = slice[len(slice)-1-i]
		slice[len(slice)-1-i] = tmp
	}
	return slice
}

func GetSPF(domain string, lookups int) (string, int) {
	if lookups >= 10 {
		return "", lookups
	}
	txts, err := net.LookupTXT(domain)
	lookups++
	if err != nil {
		log.Infof("server", "failed to get txt records for %s: %s", domain, err.Error())
		return "", lookups
	}
	// get the first spf record found
	spf := ""
	for _, txt := range txts {
		tmp := strings.ToLower(txt)
		if strings.HasPrefix(tmp, "v=spf1 ") {
			spf = txt[7:]
			break
		}
	}
	if len(spf) == 0 {
		return spf, lookups
	}
	i := strings.Index(strings.ToLower(spf), "redirect=")
	if i < 0 {
		return spf, lookups
	}
	spf = spf[i+9:]
	i = strings.Index(spf, " ")
	if i > 0 {
		spf = spf[:i]
	}
	return GetSPF(spf, lookups)
}

func CheckRBLName(host string, rbls []string) bool {
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
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return true
	}
	return CheckRBLIP(tcp.IP, rbls)
}

func CheckRBLIP(ip net.IP, rbls []string) bool {
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

func Check() int {
	conn, err := textproto.Dial("tcp", fmt.Sprintf("%s:25", Localhost))
	if err != nil {
		log.Errorf("check", "error dialing %s: %s", fmt.Sprintf("%s:25", Localhost), err.Error())
		return 1
	}
	defer conn.Close()
	code, _, err := conn.ReadCodeLine(2)
	if err != nil {
		log.Errorf("check", "unexpected welcome response (%d): %s", code, err.Error())
		return 1
	}
	err = conn.Writer.PrintfLine("NOOP %s", Healthcheck)
	if err != nil {
		log.Errorf("check", "error sending noop: %s", err.Error())
		return 1
	}
	code, message, err := conn.ReadCodeLine(2)
	if err != nil {
		log.Errorf("check", "unexpected noop response (%d): %s", code, err.Error())
		return 1
	}
	log.Infof("check", "response: %s (%d)", message, code)
	return 0
}
