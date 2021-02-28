package server

import (
	"net"
	"strings"

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
		log.Infof("failed to get txt records for %s: %s", domain, err.Error())
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
