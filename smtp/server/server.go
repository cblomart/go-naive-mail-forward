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
	extended   bool
	clientName string
	ServerName string
	mailFrom   *address.MailAddress
	rcptTo     []address.MailAddress
	processor  *process.Process
	domains    []string
	tlsConfig  *tls.Config
	dnsbl      []string
	check      bool
	nospf      bool
	sendBuffer []Response
}

type Response struct {
	Code    int
	Message string
	Extra   []string
}

func HandleSmtpConn(tcpConn net.Conn, serverName string, processor *process.Process, domains []string, dnsbl string, keyfile string, certfile string, insecuretls bool, nospf bool) {
	smtpConn := NewSmtpConn(tcpConn, serverName, processor, domains, dnsbl, keyfile, certfile, insecuretls, nospf)
	defer smtpConn.Close()
	smtpConn.ProcessMessages()
}

func NewSmtpConn(conn net.Conn, serverName string, processor *process.Process, domains []string, dnsbl string, keyfile string, certfile string, insecuretls bool, nospf bool) *Conn {
	// set tls config
	var tlsConfig *tls.Config
	certificate, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		log.Infof("error initializing tls config: %v", err)
	} else {
		// #nosec G402 tls insecure configured by config
		tlsConfig = &tls.Config{
			Certificates:       []tls.Certificate{certificate},
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecuretls,
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
		nospf:      nospf,
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
	_, err := conn.ack()
	if err != nil {
		log.Errorf("%s: %s\n", conn.showClient(), err.Error())
		return
	}
	// start the command response session
	for {
		// get command and params
		cmd, params, err := conn.request()
		if err != nil {
			// log connection  drops as debug
			if err.Error() != "connection dropped" {
				log.Errorf("%s: %s\n", conn.showClient(), err.Error())
			} else {
				log.Debugf("%s: %s\n", conn.showClient(), err.Error())
			}
			break
		}
		// check for commands that needs hello
		if utils.ContainsString(needHelo, cmd) >= 0 && !conn.hello {
			log.Errorf("%s: no hello before '%s'\n", conn.showClient(), cmd)
			_, err = conn.send(false, smtp.STATUSBADSEC, "please say hello first")
			break
		}
		quit, err := conn.execCommand(cmd, params)
		log.Debugf("%s: recieved quit:%v err:%v", conn.showClient(), quit, err)
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
		//no pipeline
		return conn.quit()
	case "HELO", "EHLO":
		//no pipeline
		return conn.helo(params, cmd == "EHLO")
	case "STARTTLS":
		//no pipline
		return conn.starttls()
	case "NOOP":
		//no pipeline
		return conn.noop(params)
	case "RSET":
		//pipeline caching
		return conn.rset()
	case "MAIL FROM":
		//pipeline caching
		return conn.mailfrom(params)
	case "RCPT TO":
		//pipeline caching
		return conn.rcptto(params)
	case "DATA":
		//no pipeline
		return conn.data()
	case "DEBUG":
		//no pipeline
		log.SetDebug(params)
		return conn.send(false, smtp.STATUSOK, log.GetDebug())
	case "TRACE":
		//no pipeline
		log.SetTrace(params)
		return conn.send(false, smtp.STATUSOK, log.GetTrace())
	default:
		return conn.unknown(cmd)
	}
}

func (conn *Conn) showClient() string {
	clientIdLock.RLock()
	defer clientIdLock.RUnlock()
	return fmt.Sprintf("%04d", conn.id)
}

func (conn *Conn) send(buffer bool, status int, message string, extra ...string) (bool, error) {
	// create new response object
	resp := Response{
		Code:    status,
		Message: message,
		Extra:   extra,
	}
	// add it to the buffer
	conn.sendBuffer = append(conn.sendBuffer, resp)
	// stop there if extended ehlo (pipelining) and buffer command
	if conn.extended && buffer {
		return false, nil
	}
	// init the globalstatus
	globalstatus := status
	// send each responses
	for _, r := range conn.sendBuffer {
		// send extra answers
		if len(r.Extra) > 0 {
			for _, e := range resp.Extra {
				log.Tracef("%s > %d-%s\n", conn.showClient(), status, e)
				_, err := fmt.Fprintf(conn.conn, "%d-%s\r\n", status, e)
				if err != nil {
					return true, err
				}
			}
		}
		// tarce message
		log.Tracef("%s > %d %s\n", conn.showClient(), r.Code, r.Message)
		// check status
		if globalstatus < r.Code {
			globalstatus = r.Code
		}
		_, err := fmt.Fprintf(conn.conn, "%d %s\r\n", r.Code, r.Message)
		if err != nil {
			return true, err
		}
	}
	// reset send buffer
	conn.sendBuffer = []Response{}
	// check if should quit
	quit := globalstatus > smtp.STATUSERROR || globalstatus == smtp.STATUSBYE
	// return
	return quit, nil
}

func (conn *Conn) ack() (bool, error) {
	// be sure the send buffer is empty
	conn.sendBuffer = []Response{}
	// hello client
	return conn.send(false, smtp.STATUSRDY, fmt.Sprintf("%s Go Naive Mail Forwarder", conn.ServerName))
}

func (conn *Conn) unknown(command string) (bool, error) {
	log.Warnf("%s: syntax error: '%s'\n", conn.showClient(), command)
	return conn.send(false, smtp.STATUSERROR, "syntax error")
}

func (conn *Conn) helo(hostname string, extended bool) (bool, error) {
	log.Debugf("%s: checking hostname: %s", conn.showClient(), hostname)
	if !conn.hostnameChecks(hostname) {
		return conn.send(false, smtp.STATUSNOACK, "malformed hostname")
	}
	log.Debugf("%s: checking if legit localhost: %s", conn.showClient(), hostname)
	// check that localhost connections comes from localhost
	if strings.EqualFold(hostname, Localhost) && !conn.ipIsLocal() {
		log.Warnf("%s: localhost but not local ip: '%s'\n", conn.showClient(), hostname)
		return conn.send(false, smtp.STATUSNOACK, "invalid localhost handshake")
	}
	log.Debugf("%s: checking RBL: %s", conn.showClient(), hostname)
	// check balacklist
	if conn.checkRBL(hostname) {
		log.Warnf("%s: known bad actor: '%s'\n", conn.showClient(), hostname)
		return conn.send(false, smtp.STATUSNOACK, "flagged in reverse black list")
	}
	conn.hello = true
	conn.extended = extended
	conn.clientName = hostname
	log.Debugf("%s: welcoming name: '%s'\n", conn.showClient(), hostname)
	// check if startls done
	_, istls := conn.conn.(*tls.Conn)
	capabilities := []string{}
	if extended {
		capabilities = append(capabilities, "PIPELINING")
		if !istls && conn.tlsConfig != nil {
			capabilities = append(capabilities, "STARTTLS")
		}
	}
	return conn.send(false, smtp.STATUSOK, fmt.Sprintf("welcome %s", hostname), capabilities...)
}

func (conn *Conn) hostnameChecks(hostname string) bool {
	// check proper domain name
	if !DomainMatch.MatchString(hostname) && !strings.EqualFold(hostname, Localhost) {
		// regex failed
		log.Warnf("%s: malformed domain: '%s'\n", conn.showClient(), hostname)
		return false
	}
	// check that this is not myself
	if strings.EqualFold(strings.TrimRight(conn.ServerName, "."), strings.TrimRight(hostname, ".")) {
		// greeted with my name... funny
		log.Warnf("%s: greeting a doppleganger: '%s'\n", conn.showClient(), hostname)
		return false
	}
	// check that the name provided can be resolved
	resolved := CheckA(hostname)
	if !resolved {
		log.Warnf("%s: remote name not resolved: '%s'\n", conn.showClient(), hostname)
		return false
	}
	return true
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
	return conn.send(false, smtp.STATUSOK, "ok")
}

func (conn *Conn) rset() (bool, error) {
	log.Debugf("%s: reseting status", conn.showClient())
	conn.mailFrom = nil
	conn.rcptTo = make([]address.MailAddress, 0)
	return conn.send(true, smtp.STATUSOK, "ok")
}

func (conn *Conn) starttls() (bool, error) {
	tlsConn, ok := conn.conn.(*tls.Conn)
	if ok {
		return conn.send(false, smtp.STATUSNOTLS, "connection already tls")
	}
	if conn.tlsConfig == nil {
		return conn.send(false, smtp.STATUSNOTLS, "tls not supported")
	}
	log.Debugf("%s: switching to tls", conn.showClient())
	// ready for TLS
	_, err := conn.send(false, smtp.STATUSRDY, "ready to discuss privately")
	if err != nil {
		log.Infof("%s: could not respond to client %s", conn.showClient(), err.Error())
		return true, err
	}
	tlsConn = tls.Server(conn.conn, conn.tlsConfig)
	log.Debugf("%s: tls handshake", conn.showClient())
	err = tlsConn.Handshake()
	if err != nil {
		log.Infof("%s: %s\n", conn.showClient(), err.Error())
		return true, fmt.Errorf("cannot read")
	}
	if err != nil {
		log.Infof("%s: failed to start tls connection %s", conn.showClient(), err.Error())
		return conn.send(false, smtp.STATUSNOPOL, "tls handshake error")
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
		return conn.send(true, smtp.STATUSNOPOL, fmt.Sprintf("from <%s> nok", param))
	}
	log.Debugf("%s: mail from %s", conn.showClient(), ma)
	conn.mailFrom = ma
	conn.rcptTo = make([]address.MailAddress, 0)
	return conn.send(true, smtp.STATUSOK, fmt.Sprintf("from <%s> ok", param))
}

func (conn *Conn) rcptto(param string) (bool, error) {
	ma, err := address.NewMailAddress(param)
	if err != nil {
		log.Infof("%s: recipient %s not valid", conn.showClient(), ma)
		return conn.send(true, smtp.STATUSNOPOL, fmt.Sprintf("rcpt <%s> nok", param))
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
		return conn.send(true, smtp.STATUSNOPOL, fmt.Sprintf("rcpt <%s> domain nok", param))
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
	return conn.send(true, smtp.STATUSOK, fmt.Sprintf("rcpt <%s> ok", param))
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
		return conn.send(false, smtp.STATUSBADSEC, "please tell me from/to before sending a message")
	}

	// warn if sending over clear text
	_, isTLS := conn.conn.(*tls.Conn)
	if !isTLS {
		log.Warnf("%s: recieving message over clear text", conn.showClient())
	}

	// accept to recieve data
	_, err := conn.send(false, smtp.STATUSACT, "shoot")
	if err != nil {
		log.Infof("%s: %s\n", conn.showClient(), err.Error())
		return true, fmt.Errorf("cannot read")
	}

	// start of data transmission
	startrec := time.Now().Unix()

	// read from input
	data, err := conn.readdata()
	if err != nil {
		log.Infof("%s: %s\n", conn.showClient(), err.Error())
	}

	// end of data transmission
	endrec := time.Now().Unix()

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
		return conn.send(false, smtp.STATUSNOPOL, "spf failed")
	}
	msgID, reject, err := conn.processor.Handle(msg)
	if err != nil {
		log.Errorf("%s:%s: error handling message: %s", conn.showClient(), msgID, err.Error())
		if reject {
			return conn.send(false, smtp.STATUSNOPOL, "mail rejected")
		}
		return conn.send(false, smtp.STATUSTMPER, "could not handle message")
	}
	log.Infof("%s: message %s recieved", conn.showClient(), msg.Id)
	elapsed := int(endrec - startrec)
	size := len(data)
	speed := size / elapsed / 1024
	return conn.send(false, smtp.STATUSOK, fmt.Sprintf("recieved %d bytes in %d secs (%.2f KBps)", size, elapsed, speed))
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
		log.Tracef("%s < %s\n", conn.showClient(), line)
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
	return conn.send(false, smtp.STATUSBYE, "goodbye")
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
	if len(command) < 4 {
		log.Debugf("%s: command too small\n", conn.showClient())
		return command, "", nil
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
	params := strings.TrimSpace(command[i+1:])
	command = strings.ToUpper(strings.TrimSpace(command[:i]))
	return command, params, nil
}
