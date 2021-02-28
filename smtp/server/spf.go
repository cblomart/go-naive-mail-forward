package server

// Implement the sender policy framework evaluation

import (
	log "cblomart/go-naive-mail-forward/logger"
	"cblomart/go-naive-mail-forward/utils"
	"fmt"
	"net"
	"strings"
)

var spfMechanismNeedParam = []string{"ip6", "ip4", "exists", "include"}

func (conn *Conn) spfCheck(domain string, lookups int) (bool, int) {
	// default to sender domain
	if len(domain) == 0 {
		domain = conn.mailFrom.Domain
	}

	// smtp should be contacted via TCP - get the IP
	tcpaddr, ok := conn.conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return true, lookups
	}
	ip := tcpaddr.IP

	// fetch the SPF records
	log.Debugf("%s: checking spf record for %s against %s", conn.showClient(), domain, tcpaddr.IP.String())
	spf, lookups := GetSPF(domain, lookups)
	if len(spf) == 0 {
		log.Debugf("%s: empty spf for %s", conn.showClient(), domain)
		return true, lookups
	}
	log.Debugf("%s: spf record for %s: %s", conn.showClient(), domain, spf)

	// evaluate SPF macros
	spf = conn.evalSPFMacros(spf, ip)

	// evaluate mechanisms
	return conn.evalMechanisms(strings.Split(spf, ";"), domain, ip, lookups)
}

//gocyclo complains because of cases
//gocyclo:ignore
func (conn *Conn) evalMechanisms(mechanisms []string, domain string, ip net.IP, lookups int) (bool, int) {
	// evaluate mechanisms
	for _, fullmechanism := range mechanisms {
		// decode mechanism
		action, mechanism, param, prefix := parseSPFMechanism(fullmechanism)
		if utils.ContainsString(spfMechanismNeedParam, mechanism) >= 0 && len(param) == 0 {
			log.Debugf("%s: skipping invalid spf mechanism %s (needs parameters)", conn.showClient(), fullmechanism)
			continue
		}
		// check mechanisms that need a param
		pass := true
		result := false
		switch mechanism {
		case "all":
			log.Debugf("%s: hitting spf catchall for %s", conn.showClient(), domain)
			return conn.evalAction(action, domain, fullmechanism), lookups
		case "ip6", "ip4":
			pass, result = conn.evalSPFIP(action, param, prefix, domain, fullmechanism, ip)
		case "a":
			pass, result, lookups = conn.evalSPFA(action, param, prefix, domain, fullmechanism, ip, lookups)
		case "mx":
			pass, result, lookups = conn.evalSPFMX(action, param, prefix, domain, fullmechanism, ip, lookups)
		case "ptr":
			pass, result, lookups = conn.evalSPFPTR(action, param, prefix, domain, fullmechanism, ip, lookups)
		case "exists":
			pass, result, lookups = conn.evalSPFExists(action, param, prefix, domain, fullmechanism, ip, lookups)
		case "include":
			log.Debugf("%s: spf for %s, checking include %s", conn.showClient(), domain, param)
			return conn.spfCheck(param, lookups)
		default:
			log.Debugf("%s: ignoring unknown spf mechanism '%s'", conn.showClient(), mechanism)
		}
		if !pass {
			return result, lookups
		}
	}
	log.Warnf("%s: no spf mechanisms matched for %s. defaulting for accept.", conn.showClient(), domain)
	return true, lookups
}

func (conn *Conn) evalSPFMacros(spf string, ip net.IP) string {
	name := ""
	names, err := net.LookupAddr(ip.String())
	if err == nil {
		name = names[0]
	}
	// variables for SPF macros
	vars := map[string]string{}
	// sender
	vars["s"] = conn.mailFrom.String()
	vars["sr"] = strings.Join(Reverse(strings.Split(vars["s"], ".")), ".")
	// local part of sender
	vars["l"] = conn.mailFrom.User
	vars["lr"] = strings.Join(Reverse(strings.Split(vars["l"], ".")), ".")
	// domain
	vars["d"] = conn.mailFrom.Domain
	vars["dr"] = strings.Join(Reverse(strings.Split(vars["d"], ".")), ".")
	// ip address
	vars["i"] = ip.String()
	vars["ir"] = strings.Join(Reverse(strings.Split(vars["i"], ".")), ".")
	// ptr of address
	if len(name) != 0 {
		vars["p"] = name
		vars["pr"] = strings.Join(Reverse(strings.Split(vars["p"], ".")), ".")
	}
	// type of address (assume IPv4)
	vars["v"] = "in-addr"
	if ip.To16() != nil {
		vars["v"] = "ip6"
	}
	// hello domain
	vars["h"] = conn.clientName
	vars["hr"] = strings.Join(Reverse(strings.Split(vars["i"], ".")), ".")
	// do replacements
	for repl := range vars {
		spf = strings.Replace(spf, fmt.Sprintf("%%{%s}", repl), vars[repl], -1)
	}
	// do final replacements
	// first replace spaces by ;
	spf = strings.ReplaceAll(spf, " ", ";")
	// replace spaces
	spf = strings.ReplaceAll(spf, "%_", " ")
	spf = strings.ReplaceAll(spf, "%_", " %20")
	// replace lingering %
	spf = strings.ReplaceAll(spf, "%%", "%")
	return spf
}

func parseSPFMechanism(fullmechanism string) (bool, string, string, string) {
	action := true // true for pas by default
	first := fullmechanism[0]
	if first != '~' && first != '?' && first != '-' && first != '+' {
		fullmechanism = fmt.Sprintf("+%s", fullmechanism)
	}
	if first == '-' {
		action = false // mechanism is '-' block
	}
	mechanism := fullmechanism[1:]
	prefix := ""
	i := strings.Index(mechanism, "/")
	if i >= 0 {
		prefix = mechanism[i+1:]
		mechanism = mechanism[:i]
	}
	param := ""
	i = strings.Index(mechanism, ":")
	if i >= 0 {
		param = mechanism[i+1:]
		mechanism = mechanism[:i]
	}
	return action, mechanism, param, prefix
}

func (conn *Conn) evalAction(action bool, domain, fullmechanism string) bool {
	if action {
		log.Debugf("%s: %s spf accept at '%s'", conn.showClient(), domain, fullmechanism)
		return true
	}
	// action should be deny then
	log.Infof("%s: %s spf reject at '%s'", conn.showClient(), domain, fullmechanism)
	return false
}

func (conn *Conn) evalSPFIP(action bool, param, prefix, domain, fullmechanism string, ip net.IP) (bool, bool) {
	if len(prefix) == 0 {
		// ip match
		if ip.String() == param {
			return false, conn.evalAction(action, domain, fullmechanism)
		}
	} else {
		_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%s", param, prefix))
		if err != nil {
			// wrong network information
			log.Debugf("%s: %s ignoring IP range check with wrong CIDR at %s", conn.showClient(), domain, fullmechanism)
			return true, false
		}
		if network.Contains(ip) {
			return false, conn.evalAction(action, domain, fullmechanism)
		}
	}
	return true, false
}

func (conn *Conn) evalSPFA(action bool, param, prefix, domain, fullmechanism string, ip net.IP, lookups int) (bool, bool, int) {
	tocheck := param
	if len(tocheck) == 0 {
		tocheck = conn.mailFrom.Domain
	}
	ars, err := net.LookupIP(tocheck)
	lookups++
	if lookups > 10 {
		log.Errorf("%s: spf for %s has too much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
		return true, true, lookups
	}
	if err != nil {
		return true, false, lookups
	}
	for _, ar := range ars {
		pass, result := conn.evalSPFIP(action, ar.String(), prefix, domain, fullmechanism, ip)
		if !pass {
			return false, result, lookups
		}
	}
	return true, false, lookups
}

func (conn *Conn) evalSPFMX(action bool, param, prefix, domain, fullmechanism string, ip net.IP, lookups int) (bool, bool, int) {
	tocheck := param
	if len(tocheck) == 0 {
		tocheck = conn.mailFrom.Domain
	}
	mxs, err := net.LookupMX(tocheck)
	lookups++
	if lookups > 10 {
		log.Errorf("%s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
		return true, true, lookups
	}
	if err != nil {
		return true, false, lookups
	}
	for _, mx := range mxs {
		ars, err := net.LookupIP(mx.Host)
		lookups++
		if lookups > 10 {
			log.Errorf("%s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
			return true, true, lookups
		}
		if err != nil {
			return true, false, lookups
		}
		for _, ar := range ars {
			pass, result := conn.evalSPFIP(action, ar.String(), prefix, domain, fullmechanism, ip)
			if !pass {
				return false, result, lookups
			}
		}
	}
	return true, false, lookups
}

func (conn *Conn) evalSPFPTR(action bool, param, prefix, domain, fullmechanism string, ip net.IP, lookups int) (bool, bool, int) {
	names, err := net.LookupAddr(ip.String())
	lookups++
	if lookups > 10 {
		log.Errorf("%s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
		return true, true, lookups
	}
	if err != nil {
		return true, false, lookups
	}
	for _, name := range names {
		ips, err := net.LookupIP(name)
		lookups++
		if lookups > 10 {
			log.Errorf("%s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
			return true, true, lookups
		}
		if err != nil {
			return true, false, lookups
		}
		for _, ip := range ips {
			if ip.Equal(ip) {
				return false, conn.evalAction(action, domain, fullmechanism), lookups
			}
		}
	}
	return true, false, lookups
}

func (conn *Conn) evalSPFExists(action bool, param, prefix, domain, fullmechanism string, ip net.IP, lookups int) (bool, bool, int) {
	ars, err := net.LookupIP(param)
	lookups++
	if lookups > 10 {
		log.Errorf("%s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
		return true, true, lookups
	}
	if err != nil {
		return true, false, lookups
	}
	if len(ars) > 0 {
		return false, conn.evalAction(action, domain, fullmechanism), lookups
	}
	return true, false, lookups
}
