//lint:file-ignore SA4006 something wrong with variable usage detection
package server

import (
	"bufio"
	"cblomart/go-naive-mail-forward/address"
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/process"
	"cblomart/go-naive-mail-forward/smtp"
	"cblomart/go-naive-mail-forward/tlsinfo"
	"cblomart/go-naive-mail-forward/utils"
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
			log.Errorf("%s: %s\n", conn.showClient(), err.Error())
			break
		}
		// check for commands that needs hello
		if utils.ContainsString(needHelo, cmd) >= 0 && !conn.hello {
			log.Errorf("%s: no hello before '%s'\n", conn.showClient(), cmd)
			err = conn.send(smtp.STATUSBADSEC, "no hello?")
			break
		}
		quit, err := conn.execCommand(cmd, params)
		if err != nil {
			log.Errorf("%s: %s\n", conn.showClient(), err.Error())
		}
		if quit {
			break
		}
	}
}

//gocyclo complains because of cases
//gocyclo:ignore
func (conn *Conn) execCommand(cmd, params string) (bool, error) {
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
		return false, conn.send(smtp.STATUSOK, log.GetDebug())
	case "TRACE":
		log.SetTrace(params)
		return false, conn.send(smtp.STATUSOK, log.GetTrace())
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

func (conn *Conn) unknown(command string) (bool, error) {
	log.Warnf("%s: syntax error: '%s'\n", conn.showClient(), command)
	return false, conn.send(smtp.STATUSERROR, "syntax error")
}

func (conn *Conn) helo(hostname string, extended bool) (bool, error) {
	err := conn.hostnameChecks(hostname)
	if err != nil {
		return true, err
	}
	// check that localhost connections comes from localhost
	if strings.EqualFold(hostname, Localhost) && !conn.ipIsLocal() {
		log.Warnf("%s: localhost but not local ip: '%s'\n", conn.showClient(), hostname)
		return true, conn.send(smtp.STATUSNOACK, "cannot continue")
	}
	// check if startls done
	_, istls := conn.conn.(*tls.Conn)
	// cehck balacklist
	if !istls && conn.checkRBL(hostname) {
		log.Warnf("%s: known bad actor: '%s'\n", conn.showClient(), hostname)
		return true, conn.send(smtp.STATUSNOACK, "cannot continue")
	}
	conn.hello = true
	conn.clientName = hostname
	log.Debugf("%s: welcoming name: '%s'\n", conn.showClient(), hostname)
	if extended && conn.tlsConfig != nil && !istls {
		return false, conn.send(smtp.STATUSOK, fmt.Sprintf("welcome %s", hostname), "STARTTLS")
	}
	return false, conn.send(smtp.STATUSOK, fmt.Sprintf("welcome %s", hostname))
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

func (conn *Conn) noop(params string) (bool, error) {
	if strings.EqualFold(params, Healthcheck) {
		conn.check = true
	}
	return false, conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) rset() (bool, error) {
	log.Debugf("%s: reseting status", conn.showClient())
	conn.mailFrom = nil
	conn.rcptTo = make([]address.MailAddress, 0)
	return false, conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) starttls() (bool, error) {
	tlsConn, ok := conn.conn.(*tls.Conn)
	if ok {
		return false, conn.send(smtp.STATUSNOTIMP, "connection already tls")
	}
	if conn.tlsConfig == nil {
		return false, conn.send(smtp.STATUSNOTIMP, "tls not supported")
	}
	log.Debugf("%s: switching to tls", conn.showClient())
	// ready for TLS
	err := conn.send(smtp.STATUSRDY, "ready to discuss privately")
	tlsConn = tls.Server(conn.conn, conn.tlsConfig)
	log.Debugf("%s: tls handshake", conn.showClient())
	err = tlsConn.Handshake()
	if err != nil {
		log.Infof("%s: %s\n", conn.showClient(), err.Error())
		return true, fmt.Errorf("cannot read")
	}
	if err != nil {
		log.Infof("%s: failed to start tls connection %s", conn.showClient(), err.Error())
		return true, conn.send(smtp.STATUSNOPOL, "tls handshake error")
	}
	log.Debugf("%s: starttls complete (%s)", conn.showClient(), tlsinfo.TlsInfo(tlsConn))
	// reset state
	conn.hello = false
	conn.conn = tlsConn
	conn.mailFrom = nil
	conn.rcptTo = make([]address.MailAddress, 0)
	return false, nil
}

func (conn *Conn) mailfrom(param string) (bool, error) {
	ma, err := address.NewMailAddress(param)
	if err != nil {
		log.Infof("%s: mail from %s not valid", conn.showClient(), ma)
		return false, conn.send(smtp.STATUSNOPOL, "bad mail address")
	}
	log.Debugf("%s: mail from %s", conn.showClient(), ma)
	conn.mailFrom = ma
	conn.rcptTo = make([]address.MailAddress, 0)
	return false, conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) rcptto(param string) (bool, error) {
	ma, err := address.NewMailAddress(param)
	if err != nil {
		log.Infof("%s: recipient %s not valid", conn.showClient(), ma)
		return false, conn.send(smtp.STATUSNOPOL, "bad mail address")
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
		return false, conn.send(smtp.STATUSNOPOL, "unaccepted domain")
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
	return false, conn.send(smtp.STATUSOK, "ok")
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

func (conn *Conn) data() (bool, error) {
	log.Debugf("%s: recieveing data", conn.showClient())

	// check if from and to ar there
	if len(conn.rcptTo) == 0 || conn.mailFrom == nil {
		// not ready to recieve a mail - i don't know where it goes!
		log.Infof("%s: refusing data without 'from' and 'to'", conn.showClient())
		return false, conn.send(smtp.STATUSBADSEC, "please tell me from/to before sending a message")
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
		return true, fmt.Errorf("cannot read")
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
		return false, conn.send(smtp.STATUSERROR, "spf failed")
	}
	msgID, reject, err := conn.processor.Handle(msg)
	if err != nil {
		log.Errorf("%s:%s: error handling message: %s", conn.showClient(), msgID, err.Error())
		if reject {
			return false, conn.send(smtp.STATUSNOPOL, "mail rejected")
		}
		return false, conn.send(smtp.STATUSTMPER, "could not handle message")
	}
	log.Infof("%s: message %s recieved", conn.showClient(), msg.Id)
	return false, conn.send(smtp.STATUSOK, "recieved 5/5")
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

func (conn *Conn) quit() (bool, error) {
	log.Debugf("%s: goodbye", conn.showClient())
	return true, conn.send(smtp.STATUSBYE, "goodbye")
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
	if len(command) < 4 {
		log.Infof("%s: command too small\n", conn.showClient())
		return "", "", fmt.Errorf("command too small")
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
