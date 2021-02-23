package smtpserver

import (
	"bufio"
	"cblomart/go-naive-mail-forward/address"
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/process"
	"cblomart/go-naive-mail-forward/smtp"
	"cblomart/go-naive-mail-forward/tlsinfo"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

//Conn is a smtp client connection
type Conn struct {
	conn       net.Conn
	hello      bool
	clientName string
	ServerName string
	Debug      bool
	mailFrom   *address.MailAddress
	rcptTo     []address.MailAddress
	processor  *process.Process
	domains    []string
	tlsConfig  *tls.Config
	dnsbl      []string
}

var DomainMatch = regexp.MustCompile("^([a-z0-9-]{1,63}\\.)+[a-z]{2,63}\\.?$")

func HandleSmtpConn(tcpConn net.Conn, serverName string, processor *process.Process, domains []string, dnsbl string, keyfile string, certfile string, debug bool) {
	smtpConn := NewSmtpConn(tcpConn, serverName, processor, domains, dnsbl, keyfile, certfile, debug)
	defer smtpConn.Close()
	smtpConn.ProcessMessages()
}

func NewSmtpConn(conn net.Conn, serverName string, processor *process.Process, domains []string, dnsbl string, keyfile string, certfile string, debug bool) *Conn {
	// set tls config
	var tlsConfig *tls.Config
	certificate, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		log.Printf("server - error initializing tls config: %v", err)
	} else {
		tlsConfig = &tls.Config{
			Certificates:       []tls.Certificate{certificate},
			InsecureSkipVerify: true,
		}
	}
	return &Conn{
		conn:       conn,
		hello:      false,
		clientName: "",
		ServerName: serverName,
		Debug:      debug,
		mailFrom:   nil,
		rcptTo:     make([]address.MailAddress, 0),
		processor:  processor,
		domains:    domains,
		tlsConfig:  tlsConfig,
		dnsbl:      strings.Split(dnsbl, ","),
	}
}

func (conn *Conn) Close() error {
	return conn.conn.Close()
}

func (conn *Conn) ProcessMessages() {
	if conn.Debug {
		log.Printf("server - %s: new connection\n", conn.showClient())
	}
	// acknowlege the new comer
	err := conn.ack()
	if err != nil {
		log.Printf("server - %s: %s\n", conn.showClient(), err.Error())
		return
	}
	// start the command response session
	for {
		cmd, params, err := conn.request()
		if err != nil {
			log.Printf("server - %s: %s\n", conn.showClient(), err.Error())
			break
		}
		if conn.Debug {
			log.Printf("server - %s: got command: '%s'\n", conn.showClient(), cmd)
			log.Printf("server - %s: got params: '%s'\n", conn.showClient(), params)
		}
		switch cmd {
		case "QUIT":
			err = conn.quit()
			return
		case "HELO", "EHLO":
			quit, nerr := conn.helo(params, cmd == "EHLO")
			if nerr != nil || quit {
				return
			}
			err = nerr
		case "STARTTLS":
			conn.starttls()
		case "NOOP":
			err = conn.noop()
		case "RSET":
			if !conn.hello {
				log.Printf("server - %s: reset without hello\n", conn.showClient())
				err = conn.send(smtp.STATUSBADSEC, "no hello")
				return
			}
			err = conn.rset()
		case "MAIL FROM":
			if !conn.hello {
				log.Printf("server - %s: recipient without hello\n", conn.showClient())
				err = conn.send(smtp.STATUSBADSEC, "no hello")
				return
			}
			err = conn.mailfrom(params)
		case "RCPT TO":
			if !conn.hello {
				log.Printf("server - %s: recipient without hello\n", conn.showClient())
				err = conn.send(smtp.STATUSBADSEC, "no hello")
				return
			}
			err = conn.rcptto(params)
		case "DATA":
			if !conn.hello {
				log.Printf("server - %s: recipient without hello\n", conn.showClient())
				err = conn.send(smtp.STATUSBADSEC, "no hello")
				return
			}
			err = conn.data()
		default:
			err = conn.unknown(cmd)
		}
		if err != nil {
			log.Printf("server - %s: %s\n", conn.showClient(), err.Error())
			break
		}
	}
}

func (conn *Conn) showClient() string {
	// get the port we are connected to
	port := ""
	tcpaddr, ok := conn.conn.RemoteAddr().(*net.TCPAddr)
	if ok {
		port = fmt.Sprintf(":%d", tcpaddr.Port)
	}
	if len(conn.clientName) == 0 {
		return conn.conn.RemoteAddr().String()
	}
	return fmt.Sprintf("%s%s", conn.clientName, port)
}

func (conn *Conn) send(status int, message string, extra ...string) error {
	if len(extra) > 0 {
		for _, e := range extra {
			if conn.Debug {
				log.Printf("server - %s > %d-%s\n", conn.showClient(), status, e)
			}
			_, err := fmt.Fprintf(conn.conn, "%d-%s\r\n", status, e)
			if err != nil {
				return err
			}
		}
	}
	if conn.Debug {
		log.Printf("server - %s > %d %s\n", conn.showClient(), status, message)
	}
	_, err := fmt.Fprintf(conn.conn, "%d %s\r\n", status, message)
	return err
}

func (conn *Conn) ack() error {
	return conn.send(smtp.STATUSRDY, fmt.Sprintf("%s Go Naive Mail Forwarder", conn.ServerName))
}

func (conn *Conn) unknown(command string) error {
	log.Printf("server - %s: syntax error: '%s'\n", conn.showClient(), command)
	return conn.send(smtp.STATUSERROR, "syntax error")
}

func (conn *Conn) helo(hostname string, extended bool) (bool, error) {
	// user lowercased hostname
	hostname = strings.ToLower(hostname)
	// check proper domain name
	if !DomainMatch.MatchString(hostname) {
		// regex failed
		log.Printf("server - %s: failed to verify: '%s'\n", conn.showClient(), hostname)
		return true, conn.send(smtp.STATUSNOACK, "cannot continue")
	}
	// check that this is not myself
	if strings.ToUpper(strings.TrimRight(conn.ServerName, ".")) == strings.ToUpper(strings.TrimRight(hostname, ".")) {
		// greeted with my name... funny
		log.Printf("server - %s: greeting a doppleganger: '%s'\n", conn.showClient(), hostname)
		return true, conn.send(smtp.STATUSNOACK, "cannot continue")
	}
	// check if startls done
	_, istls := conn.conn.(*tls.Conn)
	// cehck balacklist
	if !istls {
		if conn.checkdnsbl() {
			log.Printf("server - %s: known bad actor: '%s'\n", conn.showClient(), hostname)
			return true, conn.send(smtp.STATUSNOACK, "cannot continue")
		}
	}
	conn.hello = true
	conn.clientName = hostname
	if conn.Debug {
		log.Printf("server - %s: welcoming name: '%s'\n", conn.showClient(), hostname)
	}
	if extended && conn.tlsConfig != nil && !istls {
		return false, conn.send(smtp.STATUSOK, fmt.Sprintf("welcome %s", hostname), "STARTTLS")
	}
	return false, conn.send(smtp.STATUSOK, fmt.Sprintf("welcome %s", hostname))
}

func (conn *Conn) checkdnsbl() bool {
	if conn.Debug {
		log.Printf("server - %s: dns black list check", conn.showClient())
	}
	// determine what needs to be resolved
	tcpaddr, ok := conn.conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		// should allways be called via TCP
		return false
	}
	prefix := ""
	tmp := tcpaddr.IP.String()
	if strings.Index(tmp, ":") >= 0 {
		if conn.Debug {
			log.Printf("server - %s: black list ipv6 (contains ':'): %s", conn.showClient(), tmp)
		}
		var sb strings.Builder
		/*
			i	p6 := ExpandIp6(tmp)
				for i := len(ip6) - 1; i >= 0; i-- {
					sb.WriteByte(ip6[i])
					if i > 0 {
						sb.WriteRune('.')
					}
				}
		*/
		prefix = sb.String()

	} else {
		// ipv4
		prefix = strings.Join(Reverse(strings.Split(tmp, ".")), ".")
	}
	if len(prefix) == 0 {
		if conn.Debug {
			log.Printf("server - %s: black list prefix empty", conn.showClient())
		}
		return false
	}
	if conn.Debug {
		log.Printf("server - %s: black list check prefix %s", conn.showClient(), prefix)
	}
	// check in //
	var wg sync.WaitGroup
	wg.Add(len(conn.dnsbl))
	okChan := make(chan bool, len(conn.dnsbl))
	for _, bl := range conn.dnsbl {
		go func(blacklist string) {
			defer wg.Done()
			tocheck := fmt.Sprintf("%s.%s", prefix, blacklist)
			if conn.Debug {
				log.Printf("server - %s: dns black list looking for %s", conn.showClient(), tocheck)
			}
			ars, err := net.LookupIP(tocheck)
			if err == nil && len(ars) > 0 {
				okChan <- true
				return
			}
			okChan <- false
		}(bl)
	}
	wg.Wait()
	close(okChan)
	for v := range okChan {
		if v {
			return v
		}
	}
	return false
}

func ExpandIp6(shortip6 string) string {
	if strings.Index(shortip6, "::") >= 0 {
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

func (conn *Conn) noop() error {
	return conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) rset() error {
	if conn.Debug {
		log.Printf("server - %s: reseting status", conn.showClient())
	}
	conn.mailFrom = nil
	conn.rcptTo = make([]address.MailAddress, 0)
	return conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) starttls() error {
	tlsConn, ok := conn.conn.(*tls.Conn)
	if ok {
		return conn.send(smtp.STATUSNOTIMP, "connction already tls")
	}
	if conn.tlsConfig == nil {
		return conn.send(smtp.STATUSNOTIMP, "tls not supported")
	}
	if conn.Debug {
		log.Printf("server - %s: switching to tls", conn.showClient())
	}
	// ready for TLS
	err := conn.send(smtp.STATUSRDY, "ready to discuss privately")
	tlsConn = tls.Server(conn.conn, conn.tlsConfig)
	if conn.Debug {
		log.Printf("server - %s: tls handshake", conn.showClient())
	}
	err = tlsConn.Handshake()
	if err != nil {
		log.Printf("server - %s: %s\n", conn.showClient(), err.Error())
		return fmt.Errorf("Cannot read")
	}
	if err != nil {
		log.Printf("server - %s: failed to start tls connection %s", conn.showClient(), err.Error())
		return conn.send(smtp.STATUSNOPOL, "tls handshake error")
	}
	if conn.Debug {
		log.Printf("server - %s: starttls complete (%s)", conn.showClient(), tlsinfo.TlsInfo(tlsConn))
	}
	// reset state
	conn.hello = false
	conn.conn = tlsConn
	conn.mailFrom = nil
	conn.rcptTo = make([]address.MailAddress, 0)
	return nil
}

func (conn *Conn) mailfrom(param string) error {
	ma, err := address.NewMailAddress(param)
	if err != nil {
		log.Printf("server - %s: mail from %s not valid", conn.showClient(), ma)
		return conn.send(smtp.STATUSNOPOL, "bad mail address")
	}
	if conn.Debug {
		log.Printf("server - %s: mail from %s", conn.showClient(), ma)
	}
	conn.mailFrom = ma
	conn.rcptTo = make([]address.MailAddress, 0)
	return conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) rcptto(param string) error {
	ma, err := address.NewMailAddress(param)
	if err != nil {
		log.Printf("server - %s: recipient %s not valid", conn.showClient(), ma)
		return conn.send(smtp.STATUSNOPOL, "bad mail address")
	}
	acceptedDomain := false
	for _, domain := range conn.domains {
		if strings.ToUpper(strings.TrimRight(ma.Domain, ".")) == strings.ToUpper(strings.TrimRight(domain, ".")) {
			acceptedDomain = true
			break
		}
	}
	if !acceptedDomain {
		log.Printf("server - %s: recipient %s not in a valid domain", conn.showClient(), ma)
		return conn.send(smtp.STATUSNOPOL, "unaccepted domain")
	}
	// check if recipient already given
	found := false
	for _, to := range conn.rcptTo {
		if strings.ToUpper(strings.TrimRight(to.String(), ".")) == strings.ToUpper(strings.TrimRight(param, ".")) {
			found = true
			break
		}
	}
	if !found {
		conn.rcptTo = append(conn.rcptTo, *ma)
	}
	addresses := make([]string, len(conn.rcptTo))
	for i, ma := range conn.rcptTo {
		addresses[i] = ma.String()
	}
	if conn.Debug {
		log.Printf("server - %s: sending to %s", conn.showClient(), strings.Join(addresses, ";"))
	}
	return conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) data() error {
	if conn.Debug {
		log.Printf("server - %s: recieveing data", conn.showClient())
	}
	// check if from and to ar there
	if len(conn.rcptTo) == 0 || conn.mailFrom == nil {
		// not ready to recieve a mail - i don't know where it goes!
		log.Printf("server - %s: refusing data without 'from' and 'to'", conn.showClient())
		return conn.send(smtp.STATUSBADSEC, "please tell me from/to before sending a message")
	}
	err := conn.send(smtp.STATUSACT, "shoot")
	if err != nil {
		log.Printf("server - %s: %s\n", conn.showClient(), err.Error())
		return fmt.Errorf("Cannot read")
	}
	// get a buffer reader
	reader := bufio.NewReader(conn.conn)
	// get a text proto reader
	tp := textproto.NewReader(reader)
	var sb strings.Builder
	// get addresses of local and remote servers
	remoteaddr := conn.clientName
	tcpaddr, ok := conn.conn.RemoteAddr().(*net.TCPAddr)
	if ok {
		remoteaddr += fmt.Sprintf(" (%s)", tcpaddr.IP.String())
	}
	localaddr := conn.ServerName
	tcpaddr, ok = conn.conn.LocalAddr().(*net.TCPAddr)
	if ok {
		localaddr += fmt.Sprintf(" (%s)", tcpaddr.IP.String())
	}
	tlsinfos := ""
	tlsConn, ok := conn.conn.(*tls.Conn)
	if ok {
		tlsinfos = fmt.Sprintf(" (%s)", tlsinfo.TlsInfo(tlsConn))
	}
	// prepare trace line
	trace := fmt.Sprintf(
		"Received: from %s by %s with Golang Naive Mail Forwarder%s id %s for %s; %s",
		remoteaddr,
		localaddr,
		tlsinfos,
		"beta",
		conn.mailFrom.String(),
		time.Now().Format("02 Jan 06 15:04:05 MST"),
	)
	if conn.Debug {
		log.Printf("server - %s: trace: %s", conn.showClient(), trace)
	}
	sb.WriteString(trace)
	sb.WriteString("\r\n")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			if err == io.EOF {
				return fmt.Errorf("Connection dropped")
			}
			log.Printf("server - %s: %s\n", conn.showClient(), err.Error())
			return fmt.Errorf("Cannot read")
		}
		if conn.Debug {
			log.Printf("server - %s < %s\n", conn.showClient(), line)
		}
		if line == "." {
			break
		}
		sb.WriteString(line)
		sb.WriteString("\r\n")
	}
	// save to storage
	msg := message.Message{
		Id:   uuid.NewString(),
		From: conn.mailFrom,
		To:   conn.rcptTo,
		Data: sb.String(),
	}
	addresses := make([]string, len(msg.To))
	for i, ma := range msg.To {
		addresses[i] = ma.String()
	}
	log.Printf("server - %s: message %s (%d bytes) to %v", conn.showClient(), msg.Id, sb.Len(), strings.Join(addresses, ", "))
	accept, _ := conn.spfCheck("", 0)
	if !accept && !msg.Signed() {
		log.Printf("server - %s: message %s is not signed and refused by SPF checks", conn.showClient(), msg.Id)
		return conn.send(smtp.STATUSERROR, "spf failed")
	}
	msgId, err := conn.processor.Handle(msg)
	if err != nil {
		log.Printf("server - %s:%s: error handling message: %s", conn.showClient(), msgId, err.Error())
		return conn.send(smtp.STATUSTMPER, "could not handle message")
	}
	log.Printf("server - %s: message %s recieved", conn.showClient(), msg.Id)
	return conn.send(smtp.STATUSOK, "recieved 5/5")
}

func (conn *Conn) quit() error {
	if conn.Debug {
		log.Printf("server - %s: goodbye", conn.showClient())
	}
	return conn.send(smtp.STATUSBYE, "goodbye")
}

func (conn *Conn) request() (string, string, error) {
	// get a buffer reader
	reader := bufio.NewReader(conn.conn)
	// get a text proto reader
	tp := textproto.NewReader(reader)
	command, err := tp.ReadLine()
	if err != nil {
		if err == io.EOF {
			return "", "", fmt.Errorf("Connection dropped")
		}
		log.Printf("server - %s: %s\n", conn.showClient(), err.Error())
		return "", "", fmt.Errorf("Cannot read")
	}
	if conn.Debug {
		log.Printf("server - %s < %s\n", conn.showClient(), command)
	}
	sep := " "
	base := strings.ToUpper(command[:4])
	if base == "MAIL" || base == "RCPT" {
		sep = ":"
	}
	i := strings.Index(command, sep)
	if i == -1 {
		return strings.ToUpper(command), "", nil
	}
	params := command[i+1:]
	command = strings.ToUpper(command[:i])
	return command, params, nil
}

func (conn *Conn) spfCheck(domain string, lookups int) (bool, int) {
	// default to sender domain
	if len(domain) == 0 {
		domain = conn.mailFrom.Domain
	}
	// smtp should be contacted via TCP
	tcpaddr, ok := conn.conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return true, lookups
	}
	name := ""
	names, err := net.LookupAddr(tcpaddr.IP.String())
	if err == nil {
		name = names[0]
	}
	if conn.Debug {
		log.Printf("server - %s: checking spf record for %s against %s", conn.showClient(), domain, tcpaddr.IP.String())
	}
	spf, lookups := GetSPF(domain, lookups)
	if len(spf) == 0 {
		if conn.Debug {
			log.Printf("server - %s: empty spf for %s", conn.showClient(), domain)
		}
		return true, lookups
	}
	if conn.Debug {
		log.Printf("server - %s: spf record for %s: %s", conn.showClient(), domain, spf)
	}
	// do replacement
	// variables
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
	vars["i"] = tcpaddr.IP.String()
	vars["ir"] = strings.Join(Reverse(strings.Split(vars["i"], ".")), ".")
	// ptr of address
	if len(name) != 0 {
		vars["p"] = name
		vars["pr"] = strings.Join(Reverse(strings.Split(vars["p"], ".")), ".")
	}
	// type of address (assume IPv4)
	vars["v"] = "in-addr"
	if tcpaddr.IP.To16() != nil {
		vars["v"] = "ip6"
	}
	// hello domain
	vars["h"] = conn.clientName
	vars["hr"] = strings.Join(Reverse(strings.Split(vars["i"], ".")), ".")
	// do replacements
	for repl := range vars {
		spf = strings.Replace(spf, fmt.Sprintf("%%{%s}", repl), vars[repl], -1)
	}
	// evaluate mechanisms
	for _, fullmechanism := range strings.Split(spf, " ") {
		// replace spaces
		fullmechanism = strings.Replace(fullmechanism, "%_", " ", -1)
		fullmechanism = strings.Replace(fullmechanism, "%_", " %20", -1)
		// replace lingering %
		fullmechanism = strings.Replace(fullmechanism, "%%", "%", -1)
		// now we have a clean mechanism
		action := "+"
		first := string(fullmechanism[0])
		if first == "~" || first == "?" || first == "-" || first == "+" {
			action = first
			if first == "~" || first == "?" {
				action = "+"
			}
		} else {
			fullmechanism = fmt.Sprintf("+%s", fullmechanism)
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
		switch mechanism {
		case "all":
			if conn.Debug {
				log.Printf("server - %s: hitting spf catchall for %s", conn.showClient(), domain)
			}
			return conn.evalAction(domain, action, fullmechanism), lookups
		case "ip6", "ip4":
			if len(param) == 0 {
				continue
			}
			if len(prefix) == 0 {
				// ip match
				if tcpaddr.IP.String() == param {
					return conn.evalAction(domain, action, fullmechanism), lookups
				}
			} else {
				_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%s", param, prefix))
				if err != nil {
					// wrong network information
					continue
				}
				if network.Contains(tcpaddr.IP) {
					return conn.evalAction(domain, action, fullmechanism), lookups
				}
			}
		case "a":
			tocheck := param
			if len(tocheck) == 0 {
				tocheck = conn.mailFrom.Domain
			}
			ars, err := net.LookupIP(tocheck)
			lookups++
			if lookups > 10 {
				log.Printf("server - %s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
				return true, lookups
			}
			if err != nil {
				continue
			}
			for _, ar := range ars {
				if len(prefix) == 0 {
					if ar.Equal(tcpaddr.IP) {
						return conn.evalAction(domain, action, fullmechanism), lookups
					}
				} else {
					strnetwork := fmt.Sprintf("%s/%s", ar.String(), prefix)
					_, network, err := net.ParseCIDR(strnetwork)
					if err != nil {
						continue
					}
					if network.Contains(tcpaddr.IP) {
						return conn.evalAction(domain, action, fullmechanism), lookups
					}
				}
			}
		case "mx":
			tocheck := param
			if len(tocheck) == 0 {
				tocheck = conn.mailFrom.Domain
			}
			mxs, err := net.LookupMX(tocheck)
			lookups++
			if lookups > 10 {
				log.Printf("server - %s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
				return true, lookups
			}
			if err != nil {
				continue
			}
			for _, mx := range mxs {
				ars, err := net.LookupIP(mx.Host)
				lookups++
				if lookups > 10 {
					log.Printf("server - %s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
					return true, lookups
				}
				if err != nil {
					continue
				}
				for _, ar := range ars {
					if len(prefix) == 0 {
						if ar.Equal(tcpaddr.IP) {
							return conn.evalAction(domain, action, fullmechanism), lookups
						}
					} else {
						strnetwork := fmt.Sprintf("%s/%s", ar.String(), prefix)
						_, network, err := net.ParseCIDR(strnetwork)
						if err != nil {
							continue
						}
						if network.Contains(tcpaddr.IP) {
							return conn.evalAction(domain, action, fullmechanism), lookups
						}
					}
				}
			}
		case "ptr":
			names, err := net.LookupAddr(tcpaddr.IP.String())
			lookups++
			if lookups > 10 {
				log.Printf("server - %s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
				return true, lookups
			}
			if err != nil {
				continue
			}
			for _, name := range names {
				ips, err := net.LookupIP(name)
				lookups++
				if lookups > 10 {
					log.Printf("server - %s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
					return true, lookups
				}
				if err != nil {
					continue
				}
				for _, ip := range ips {
					if ip.Equal(tcpaddr.IP) {
						return conn.evalAction(domain, action, fullmechanism), lookups
					}
				}
			}
		case "exists":
			if len(param) == 0 {
				continue
			}
			ars, err := net.LookupIP(param)
			lookups++
			if lookups > 10 {
				log.Printf("server - %s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
				return true, lookups
			}
			if err != nil {
				continue
			}
			if len(ars) > 0 {
				return conn.evalAction(domain, action, fullmechanism), lookups
			}
		case "include":
			if len(param) == 0 {
				continue
			}
			if conn.Debug {
				log.Printf("server - %s: spf for %s, checking include %s", conn.showClient(), domain, param)
			}
			return conn.spfCheck(param, lookups)
		default:
			if conn.Debug {
				log.Printf("server - %s: ignoring unknown spf mechanism '%s'", conn.showClient(), mechanism)
			}
		}
	}
	if conn.Debug {
		log.Printf("server - %s: no spf mechanisms matched for %s. defaulting for accept!", conn.showClient(), domain)
	}
	return true, lookups
}

func (conn *Conn) evalAction(domain, action, fullmechanism string) bool {
	if action == "+" {
		if conn.Debug {
			log.Printf("server - %s: %s spf accept at '%s'", conn.showClient(), domain, fullmechanism)
		}
		return true
	}
	// action should be deny then
	log.Printf("server - %s: %s spf reject at '%s'", conn.showClient(), domain, fullmechanism)
	return false
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
		log.Printf("server - failed to get txt records for %s: %s", domain, err.Error())
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
