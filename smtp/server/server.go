//lint:file-ignore SA4006 something wrong with variable usage detection
package server

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
	"net"
	"net/textproto"
	"regexp"
	"strings"
	"sync"
	"time"

	log "cblomart/go-naive-mail-forward/logger"

	"github.com/google/uuid"
)

const (
	Localhost   = "localhost"
	Healthcheck = "healthcheck"
)

var (
	Trace        = false
	Debug        = false
	DomainMatch  = regexp.MustCompile(`(?i)^([a-z0-9-]{1,63}\.)+[a-z]{2,63}\.?$`)
	clientId     = 0
	clientIdLock = sync.RWMutex{}
	needHelo     = []string{"RSET", "MAIL FROM", "RCPT TO", "DATA", "STARTTLS"}
)

//Conn is a smtp client connection
type Conn struct {
	id         int
	conn       net.Conn
	hello      bool
	clientName string
	ServerName string
	mailFrom   *address.MailAddress
	rcptTo     []address.MailAddress
	processor  *process.Process
	domains    []string
	tlsConfig  *tls.Config
	dnsbl      []string
	check      bool
}

func HandleSmtpConn(tcpConn net.Conn, serverName string, processor *process.Process, domains []string, dnsbl string, keyfile string, certfile string) {
	smtpConn := NewSmtpConn(tcpConn, serverName, processor, domains, dnsbl, keyfile, certfile)
	defer smtpConn.Close()
	smtpConn.ProcessMessages()
}

func NewSmtpConn(conn net.Conn, serverName string, processor *process.Process, domains []string, dnsbl string, keyfile string, certfile string) *Conn {
	// set tls config
	var tlsConfig *tls.Config
	certificate, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		log.Infof("error initializing tls config: %v", err)
	} else {
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		}
	}
	clientIdLock.Lock()
	defer clientIdLock.Unlock()
	id := clientId + 1
	clientId++
	return &Conn{
		id:         id,
		conn:       conn,
		hello:      false,
		clientName: "",
		ServerName: serverName,
		mailFrom:   nil,
		rcptTo:     make([]address.MailAddress, 0),
		processor:  processor,
		domains:    domains,
		tlsConfig:  tlsConfig,
		dnsbl:      strings.Split(dnsbl, ","),
	}
}

func (conn *Conn) Close() error {
	clientIdLock.Lock()
	defer clientIdLock.Unlock()
	clientId--
	return conn.conn.Close()
}

func (conn *Conn) ProcessMessages() {
	log.Debugf("%s: new connection from %s\n", conn.showClient(), conn.conn.RemoteAddr().String())
	// acknowlege the new comer
	err := conn.ack()
	if err != nil {
		log.Errorf("%s: %s\n", conn.showClient(), err.Error())
		return
	}
	// start the command response session
	for {
		// get command and params
		cmd, params, err := conn.request()
		if err != nil {
			log.Debugf("%s: %s\n", conn.showClient(), err.Error())
			break
		}
		if Contains(needHelo, cmd) {
			log.Errorf("%s: no hello before '%s'\n", conn.showClient(), cmd)
			err = conn.send(smtp.STATUSBADSEC, "no hello?")
			break
		}
		err = conn.execCommand(cmd, params)
		if err != nil {
			log.Errorf("%s: %s\n", conn.showClient(), err.Error())
			break
		}
	}
}

//gocyclo complains because of cases
//gocyclo:ignore
func (conn *Conn) execCommand(cmd, params string) error {
	switch cmd {
	case "QUIT":
		return conn.quit()
	case "HELO", "EHLO":
		return conn.helo(params, cmd == "EHLO")
	case "STARTTLS":
		return conn.starttls()
	case "NOOP":
		return conn.noop(params)
	case "RSET":
		return conn.rset()
	case "MAIL FROM":
		return conn.mailfrom(params)
	case "RCPT TO":
		return conn.rcptto(params)
	case "DATA":
		return conn.data()
	case "DEBUG":
		log.SetDebug(params)
		return conn.send(smtp.STATUSOK, log.GetDebug())
	case "TRACE":
		log.SetTrace(params)
		return conn.send(smtp.STATUSOK, log.GetTrace())
	default:
		return conn.unknown(cmd)
	}
}

func (conn *Conn) showClient() string {
	clientIdLock.RLock()
	defer clientIdLock.RUnlock()
	return fmt.Sprintf("%04d", conn.id)
}

func (conn *Conn) send(status int, message string, extra ...string) error {
	if len(extra) > 0 {
		for _, e := range extra {
			log.Tracef("%s > %d-%s\n", conn.showClient(), status, e)
			_, err := fmt.Fprintf(conn.conn, "%d-%s\r\n", status, e)
			if err != nil {
				return err
			}
		}
	}
	log.Tracef("%s > %d %s\n", conn.showClient(), status, message)
	_, err := fmt.Fprintf(conn.conn, "%d %s\r\n", status, message)
	return err
}

func (conn *Conn) ack() error {
	return conn.send(smtp.STATUSRDY, fmt.Sprintf("%s Go Naive Mail Forwarder", conn.ServerName))
}

func (conn *Conn) unknown(command string) error {
	log.Warnf("%s: syntax error: '%s'\n", conn.showClient(), command)
	return conn.send(smtp.STATUSERROR, "syntax error")
}

func (conn *Conn) helo(hostname string, extended bool) error {
	err := conn.hostnameChecks(hostname)
	if err != nil {
		return err
	}
	// check that localhost connections comes from localhost
	if strings.EqualFold(hostname, Localhost) && !conn.ipIsLocal() {
		log.Warnf("%s: localhost but not local ip: '%s'\n", conn.showClient(), hostname)
		return conn.send(smtp.STATUSNOACK, "cannot continue")
	}
	// check if startls done
	_, istls := conn.conn.(*tls.Conn)
	// cehck balacklist
	if !istls && conn.checkRBL() {
		log.Warnf("%s: known bad actor: '%s'\n", conn.showClient(), hostname)
		return conn.send(smtp.STATUSNOACK, "cannot continue")
	}
	conn.hello = true
	conn.clientName = hostname
	log.Debugf("%s: welcoming name: '%s'\n", conn.showClient(), hostname)
	if extended && conn.tlsConfig != nil && !istls {
		return conn.send(smtp.STATUSOK, fmt.Sprintf("welcome %s", hostname), "STARTTLS")
	}
	return conn.send(smtp.STATUSOK, fmt.Sprintf("welcome %s", hostname))
}

func (conn *Conn) hostnameChecks(hostname string) error {
	// check proper domain name
	if !DomainMatch.MatchString(hostname) && !strings.EqualFold(hostname, Localhost) {
		// regex failed
		log.Warnf("%s: malformed domain: '%s'\n", conn.showClient(), hostname)
		return conn.send(smtp.STATUSNOACK, "cannot continue")
	}
	// check that this is not myself
	if strings.EqualFold(strings.TrimRight(conn.ServerName, "."), strings.TrimRight(hostname, ".")) {
		// greeted with my name... funny
		log.Warnf("%s: greeting a doppleganger: '%s'\n", conn.showClient(), hostname)
		return conn.send(smtp.STATUSNOACK, "cannot continue")
	}
	// check that the name provided can be resolved
	resolved := CheckA(hostname)
	if !resolved {
		log.Warnf("%s: remote name not resolved: '%s'\n", conn.showClient(), hostname)
		return conn.send(smtp.STATUSNOACK, "cannot continue")
	}
	return nil
}

func (conn *Conn) ipIsLocal() bool {
	tcpconn, ok := conn.conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		log.Debugf("%s: localhost connection not on tcp\n", conn.showClient())
		return false
	}
	if !tcpconn.IP.IsLoopback() {
		log.Debugf("%s: localhost connection not on loopback\n", conn.showClient())
		return false
	}
	return true
}

func (conn *Conn) checkRBL() bool {
	// check dns blacklist per ip
	bad := CheckRBLAddr(conn.conn.RemoteAddr(), conn.dnsbl)
	if !bad {
		// check dns blacklist per name
		bad = CheckRBLName(conn.clientName, conn.dnsbl)
	}
	return bad
}

func (conn *Conn) noop(params string) error {
	if strings.EqualFold(params, Healthcheck) {
		conn.check = true
	}
	return conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) rset() error {
	log.Debugf("%s: reseting status", conn.showClient())
	conn.mailFrom = nil
	conn.rcptTo = make([]address.MailAddress, 0)
	return conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) starttls() error {
	tlsConn, ok := conn.conn.(*tls.Conn)
	if ok {
		return conn.send(smtp.STATUSNOTIMP, "connection already tls")
	}
	if conn.tlsConfig == nil {
		return conn.send(smtp.STATUSNOTIMP, "tls not supported")
	}
	log.Debugf("%s: switching to tls", conn.showClient())
	// ready for TLS
	err := conn.send(smtp.STATUSRDY, "ready to discuss privately")
	tlsConn = tls.Server(conn.conn, conn.tlsConfig)
	log.Debugf("%s: tls handshake", conn.showClient())
	err = tlsConn.Handshake()
	if err != nil {
		log.Infof("%s: %s\n", conn.showClient(), err.Error())
		return fmt.Errorf("cannot read")
	}
	if err != nil {
		log.Infof("%s: failed to start tls connection %s", conn.showClient(), err.Error())
		return conn.send(smtp.STATUSNOPOL, "tls handshake error")
	}
	log.Debugf("%s: starttls complete (%s)", conn.showClient(), tlsinfo.TlsInfo(tlsConn))
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
		log.Infof("%s: mail from %s not valid", conn.showClient(), ma)
		return conn.send(smtp.STATUSNOPOL, "bad mail address")
	}
	log.Debugf("%s: mail from %s", conn.showClient(), ma)
	conn.mailFrom = ma
	conn.rcptTo = make([]address.MailAddress, 0)
	return conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) rcptto(param string) error {
	ma, err := address.NewMailAddress(param)
	if err != nil {
		log.Infof("%s: recipient %s not valid", conn.showClient(), ma)
		return conn.send(smtp.STATUSNOPOL, "bad mail address")
	}
	acceptedDomain := false
	for _, domain := range conn.domains {
		if strings.EqualFold(strings.TrimRight(ma.Domain, "."), strings.TrimRight(domain, ".")) {
			acceptedDomain = true
			break
		}
	}
	if !acceptedDomain {
		log.Infof("%s: recipient %s not in a valid domain", conn.showClient(), ma)
		return conn.send(smtp.STATUSNOPOL, "unaccepted domain")
	}
	// check if recipient already given
	found := false
	for _, to := range conn.rcptTo {
		if strings.EqualFold(strings.TrimRight(to.String(), "."), strings.TrimRight(param, ".")) {
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
	log.Debugf("%s: sending to %s", conn.showClient(), strings.Join(addresses, ";"))
	return conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) getTrace() string {
	// get information on the remove address
	remoteaddr := conn.clientName
	tcpaddr, ok := conn.conn.RemoteAddr().(*net.TCPAddr)
	if ok {
		remoteaddr += fmt.Sprintf(" (%s)", tcpaddr.IP.String())
	}

	// get information on the remte address
	localaddr := conn.ServerName
	tcpaddr, ok = conn.conn.LocalAddr().(*net.TCPAddr)
	if ok {
		localaddr += fmt.Sprintf(" (%s)", tcpaddr.IP.String())
	}

	// get information on TLS encryption
	tlsinfos := ""
	tlsConn, ok := conn.conn.(*tls.Conn)
	if ok {
		tlsinfos = fmt.Sprintf(" (%s)", tlsinfo.TlsInfo(tlsConn))
	}

	// return trace line
	return fmt.Sprintf(
		"Received: from %s by %s with Golang Naive Mail Forwarder%s id %s for %s; %s",
		remoteaddr,
		localaddr,
		tlsinfos,
		"beta",
		conn.mailFrom.String(),
		time.Now().Format("02 Jan 06 15:04:05 MST"),
	)
}

func (conn *Conn) data() error {
	log.Debugf("%s: recieveing data", conn.showClient())

	// check if from and to ar there
	if len(conn.rcptTo) == 0 || conn.mailFrom == nil {
		// not ready to recieve a mail - i don't know where it goes!
		log.Infof("%s: refusing data without 'from' and 'to'", conn.showClient())
		return conn.send(smtp.STATUSBADSEC, "please tell me from/to before sending a message")
	}

	// warn if sending over clear text
	_, isTls := conn.conn.(*tls.Conn)
	if !isTls {
		log.Warnf("%s: recieving message over clear text", conn.showClient())
	}

	// accept to recieve data
	err := conn.send(smtp.STATUSACT, "shoot")
	if err != nil {
		log.Infof("%s: %s\n", conn.showClient(), err.Error())
		return fmt.Errorf("cannot read")
	}

	// read from input
	data, err := conn.readdata()
	if err != nil {
		log.Infof("%s: %s\n", conn.showClient(), err.Error())
	}

	// save to storage
	msg := message.Message{
		Id:   uuid.NewString(),
		From: conn.mailFrom,
		To:   conn.rcptTo,
		Data: data,
	}
	log.Infof("%s: message %s (%d bytes) to %v", conn.showClient(), msg.Id, len(data), msg.Recipients())
	accept, _ := conn.spfCheck("", 0)
	if !accept && !msg.Signed() {
		log.Warnf("%s: message %s is not signed and refused by SPF checks", conn.showClient(), msg.Id)
		return conn.send(smtp.STATUSERROR, "spf failed")
	}
	msgID, reject, err := conn.processor.Handle(msg)
	if err != nil {
		log.Errorf("%s:%s: error handling message: %s", conn.showClient(), msgID, err.Error())
		if reject {
			return conn.send(smtp.STATUSNOPOL, "mail rejected")
		}
		return conn.send(smtp.STATUSTMPER, "could not handle message")
	}
	log.Infof("%s: message %s recieved", conn.showClient(), msg.Id)
	return conn.send(smtp.STATUSOK, "recieved 5/5")
}

func (conn *Conn) readdata() (string, error) {
	// get a buffer reader
	reader := bufio.NewReader(conn.conn)

	// get a text proto reader
	tp := textproto.NewReader(reader)

	var sb strings.Builder
	// get trace information
	trace := conn.getTrace()
	log.Debugf("%s: trace: %s", conn.showClient(), trace)
	sb.WriteString(trace)
	sb.WriteString("\r\n")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			log.Infof("%s: %s\n", conn.showClient(), err.Error())
			return "", fmt.Errorf("cannot read")
		}
		if Debug {
			log.Infof("%s < %s\n", conn.showClient(), line)
		}
		if line == "." {
			break
		}
		sb.WriteString(line)
		sb.WriteString("\r\n")
	}
	return sb.String(), nil
}

func (conn *Conn) quit() error {
	log.Debugf("%s: goodbye", conn.showClient())
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
			return "", "", fmt.Errorf("connection dropped")
		}
		log.Infof("%s: %s\n", conn.showClient(), err.Error())
		return "", "", fmt.Errorf("cannot read")
	}
	if !IsAsciiPrintable(command) {
		log.Infof("%s: command contains non ascii printable characters\n", conn.showClient())
		return "", "", fmt.Errorf("command contains non ascii printable characters")
	}
	log.Tracef("%s < %s\n", conn.showClient(), command)
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
	log.Debugf("%s: checking spf record for %s against %s", conn.showClient(), domain, tcpaddr.IP.String())
	spf, lookups := GetSPF(domain, lookups)
	if len(spf) == 0 {
		log.Debugf("%s: empty spf for %s", conn.showClient(), domain)
		return true, lookups
	}
	log.Debugf("%s: spf record for %s: %s", conn.showClient(), domain, spf)
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
		action := true // false for pass by default
		first := fullmechanism[0]
		if first != '~' && first != '?' && first != '-' && first != '+' {
			fullmechanism = fmt.Sprintf("+%s", fullmechanism)
		}
		if first == '-' {
			action = false
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
			log.Debugf("%s: hitting spf catchall for %s", conn.showClient(), domain)
			return conn.evalAction(action, domain, fullmechanism), lookups
		case "ip6", "ip4":
			if len(param) == 0 {
				continue
			}
			if len(prefix) == 0 {
				// ip match
				if tcpaddr.IP.String() == param {
					return conn.evalAction(action, domain, fullmechanism), lookups
				}
			} else {
				_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%s", param, prefix))
				if err != nil {
					// wrong network information
					continue
				}
				if network.Contains(tcpaddr.IP) {
					return conn.evalAction(action, domain, fullmechanism), lookups
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
				log.Errorf("%s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
				return true, lookups
			}
			if err != nil {
				continue
			}
			for _, ar := range ars {
				if len(prefix) == 0 {
					if ar.Equal(tcpaddr.IP) {
						return conn.evalAction(action, domain, fullmechanism), lookups
					}
				} else {
					strnetwork := fmt.Sprintf("%s/%s", ar.String(), prefix)
					_, network, err := net.ParseCIDR(strnetwork)
					if err != nil {
						continue
					}
					if network.Contains(tcpaddr.IP) {
						return conn.evalAction(action, domain, fullmechanism), lookups
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
				log.Errorf("%s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
				return true, lookups
			}
			if err != nil {
				continue
			}
			for _, mx := range mxs {
				ars, err := net.LookupIP(mx.Host)
				lookups++
				if lookups > 10 {
					log.Errorf("%s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
					return true, lookups
				}
				if err != nil {
					continue
				}
				for _, ar := range ars {
					if len(prefix) == 0 {
						if ar.Equal(tcpaddr.IP) {
							return conn.evalAction(action, domain, fullmechanism), lookups
						}
					} else {
						strnetwork := fmt.Sprintf("%s/%s", ar.String(), prefix)
						_, network, err := net.ParseCIDR(strnetwork)
						if err != nil {
							continue
						}
						if network.Contains(tcpaddr.IP) {
							return conn.evalAction(action, domain, fullmechanism), lookups
						}
					}
				}
			}
		case "ptr":
			names, err := net.LookupAddr(tcpaddr.IP.String())
			lookups++
			if lookups > 10 {
				log.Errorf("%s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
				return true, lookups
			}
			if err != nil {
				continue
			}
			for _, name := range names {
				ips, err := net.LookupIP(name)
				lookups++
				if lookups > 10 {
					log.Errorf("%s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
					return true, lookups
				}
				if err != nil {
					continue
				}
				for _, ip := range ips {
					if ip.Equal(tcpaddr.IP) {
						return conn.evalAction(action, domain, fullmechanism), lookups
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
				log.Errorf("%s: spf for %s has much dns lookups at '%s'", conn.showClient(), domain, fullmechanism)
				return true, lookups
			}
			if err != nil {
				continue
			}
			if len(ars) > 0 {
				return conn.evalAction(action, domain, fullmechanism), lookups
			}
		case "include":
			if len(param) == 0 {
				continue
			}
			log.Debugf("%s: spf for %s, checking include %s", conn.showClient(), domain, param)
			return conn.spfCheck(param, lookups)
		default:
			log.Debugf("%s: ignoring unknown spf mechanism '%s'", conn.showClient(), mechanism)
		}
	}
	log.Warnf("%s: no spf mechanisms matched for %s. defaulting for accept.", conn.showClient(), domain)
	return true, lookups
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
