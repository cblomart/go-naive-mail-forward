package server

import (
	"bufio"
	"bytes"
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
	"strconv"
	"strings"
	"sync"
	"time"

	log "cblomart/go-naive-mail-forward/logger"

	//"github.com/google/uuid"

	"github.com/lithammer/shortuuid"
)

const (
	Localhost       = "localhost"
	Healthcheck     = "healthcheck"
	timeoutDuration = 100 * time.Millisecond
)

var (
	Trace         = false
	Debug         = false
	DomainMatch   = regexp.MustCompile(`(?i)^([a-z0-9-]{1,63}\.)+[a-z]{2,63}\.?$`)
	BdataParams   = regexp.MustCompile(`(?i)^[0-9]+( +LAST)?$`)
	whitespace    = regexp.MustCompile(`\s+`)
	clientId      = 0
	clientIdLock  = sync.RWMutex{}
	needHelo      = []string{"RSET", "MAIL FROM", "RCPT TO", "DATA", "BDAT", "STARTTLS"}
	noBdatDomains = []string{}
)

//Conn is a smtp client connection
type Conn struct {
	id             int
	conn           net.Conn
	acked          bool
	hello          bool
	close          bool
	extended       bool
	clientName     string
	ServerName     string
	mailFrom       *address.MailAddress
	rcptTo         []address.MailAddress
	processor      *process.Process
	domains        []string
	tlsConfig      *tls.Config
	dnsbl          []string
	check          bool
	nospf          bool
	responseBuffer []*Response
	commandBuffer  string
	dataBuffer     *bytes.Buffer
	dataStart      int64
	dataFinish     int64
}

type Response struct {
	Code    int
	Message string
	Extra   []string
}

// String show the response on one string
func (r *Response) String() string {
	return fmt.Sprintf("%d %s (+%s)", r.Code, r.Message, strings.Join(r.Extra, ","))
}

// Lines returns the lines to send back to the client
func (r *Response) Lines() []string {
	lines := make([]string, len(r.Extra)+1)
	for i, e := range r.Extra {
		lines[i] = fmt.Sprintf("%d-%s\r\n", r.Code, e)
	}
	lines[len(lines)-1] = fmt.Sprintf("%d %s\r\n", r.Code, r.Message)
	return lines
}

// HandleSMTPConn handles a smtp connection
func HandleSMTPConn(conn *net.TCPConn, serverName string, processor *process.Process, domains []string, dnsbl string, keyfile string, certfile string, insecuretls bool, nospf bool) {
	smtpConn := GetSMTPConn(conn, serverName, processor, domains, dnsbl, keyfile, certfile, insecuretls, nospf)
	log.Debugf("%s: new connection from %s", smtpConn.showClient(), conn.RemoteAddr().String())
	defer smtpConn.Close()
	log.Debugf("%s: starting processing commands", smtpConn.showClient())
	smtpConn.processMessages()
}

// GetSMTPConn updates to connection to a smtp connection
func GetSMTPConn(conn *net.TCPConn, serverName string, processor *process.Process, domains []string, dnsbl string, keyfile string, certfile string, insecuretls bool, nospf bool) *Conn {
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
	id := clientId + 1
	clientId++
	smtpConn := Conn{
		id:             id,
		conn:           conn,
		acked:          false,
		hello:          false,
		clientName:     "",
		ServerName:     serverName,
		mailFrom:       nil,
		rcptTo:         make([]address.MailAddress, 0),
		processor:      processor,
		domains:        domains,
		tlsConfig:      tlsConfig,
		dnsbl:          strings.Split(dnsbl, ","),
		nospf:          nospf,
		responseBuffer: []*Response{},
		dataBuffer:     &bytes.Buffer{},
	}
	return &smtpConn
}

// Close the smtp server connection
func (conn *Conn) Close() error {
	clientId--
	return conn.conn.Close()
}

func (conn *Conn) writeall() error {
	// write all responses from response buffer
	for _, r := range conn.responseBuffer {
		for _, line := range r.Lines() {
			log.Tracef("%s: > %s", conn.showClient(), line)
			_, err := conn.conn.Write([]byte(line))
			if err != nil {
				return err
			}
		}
	}
	conn.responseBuffer = []*Response{}
	return nil
}

func (conn *Conn) read() error {
	buffer := make([]byte, 1024)
	n, err := conn.conn.Read(buffer)
	if err != nil {
		return err
	}
	conn.commandBuffer += string(buffer[:n])
	for {
		i := strings.Index(conn.commandBuffer, "\n")
		if i < 0 {
			break
		}
		line := whitespace.ReplaceAllString(conn.commandBuffer[:i], " ")
		line = strings.TrimSpace(line)
		conn.commandBuffer = conn.commandBuffer[i+1:]
		log.Tracef("%s: < %s", conn.showClient(), line)
		if conn.processLine(line) {
			break
		}
	}
	return nil
}

func (conn *Conn) processMessages() {
	// acknowlege the new comer
	conn.ack()
	err := conn.writeall()
	if err != nil {
		log.Errorf("%s: write error %s", conn.showClient(), err.Error())
	}
	// start the command response session
	for !conn.close {
		err := conn.read()
		if err == io.EOF {
			log.Debugf("%s: read error %s", conn.showClient(), err.Error())
			break
		}
		if err != nil {
			log.Errorf("%s: read error %s", conn.showClient(), err.Error())
			break
		}
		err = conn.writeall()
		if err != nil {
			if conn.close {
				log.Debugf("%s: wrrte error %s", conn.showClient(), err.Error())
			} else {
				log.Errorf("%s: wrrte error %s", conn.showClient(), err.Error())
			}
		}
	}
}

func (conn *Conn) processLine(line string) bool {
	// get command and params
	cmd, params, err := conn.parse(line)
	if err != nil {
		log.Errorf("%s: %s\n", conn.showClient(), err.Error())
		return true
	}
	// check for commands that needs hello
	if utils.ContainsString(needHelo, cmd) >= 0 && !conn.hello {
		log.Errorf("%s: no hello before '%s'\n", conn.showClient(), cmd)
		conn.send(smtp.STATUSBADSEC, "please say hello first")
		return true
	}
	conn.execCommand(cmd, params)
	return cmd == "QUIT"
}

//gocyclo complains because of cases
//gocyclo:ignore
func (conn *Conn) execCommand(cmd, params string) {
	switch cmd {
	case "QUIT":
		//no pipeline
		conn.quit()
	case "HELO", "EHLO":
		//no pipeline
		conn.helo(params, cmd == "EHLO")
	case "STARTTLS":
		//no pipline
		conn.starttls()
	case "NOOP":
		//no pipeline
		conn.noop(params)
	case "RSET":
		//pipeline caching
		conn.rset()
	case "MAIL FROM":
		//pipeline caching
		conn.mailfrom(params)
	case "RCPT TO":
		//pipeline caching
		conn.rcptto(params)
	case "DATA":
		//no pipeline
		conn.data()
	case "BDAT":
		//no pipeline
		conn.binarydata(params)
	case "DEBUG":
		//no pipeline
		log.SetDebug(params)
		conn.send(smtp.STATUSOK, log.GetDebug())
	case "TRACE":
		//no pipeline
		log.SetTrace(params)
		conn.send(smtp.STATUSOK, log.GetTrace())
	default:
		conn.unknown(cmd)
	}
}

func (conn *Conn) showClient() string {
	clientIdLock.RLock()
	defer clientIdLock.RUnlock()
	return fmt.Sprintf("%04d", conn.id)
}

func (conn *Conn) send(status int, message string, extra ...string) {
	// create new response object
	resp := Response{
		Code:    status,
		Message: message,
		Extra:   extra,
	}
	// add it to the buffer
	conn.responseBuffer = append(conn.responseBuffer, &resp)
}

func (conn *Conn) ack() {
	log.Debugf("%s: acknowledging client", conn.showClient())
	// hello client
	conn.send(smtp.STATUSRDY, fmt.Sprintf("%s Go Naive Mail Forwarder", conn.ServerName))
	conn.acked = true
}

func (conn *Conn) unknown(command string) {
	log.Warnf("%s: syntax error: '%s'\n", conn.showClient(), command)
	conn.send(smtp.STATUSERROR, "syntax error")
}

func (conn *Conn) helo(hostname string, extended bool) {
	hostname = strings.ToLower(strings.TrimRight(hostname, "."))
	log.Debugf("%s: checking hostname: %s", conn.showClient(), hostname)
	if !conn.hostnameChecks(hostname) {
		conn.send(smtp.STATUSNOACK, "malformed hostname")
		conn.close = true
		return
	}
	log.Debugf("%s: checking if legit localhost: %s", conn.showClient(), hostname)
	// check that localhost connections comes from localhost
	if strings.EqualFold(hostname, Localhost) && !conn.ipIsLocal() {
		log.Warnf("%s: localhost but not local ip: '%s'\n", conn.showClient(), hostname)
		conn.send(smtp.STATUSNOACK, "invalid localhost handshake")
		conn.close = true
		return
	}
	log.Debugf("%s: checking RBL: %s", conn.showClient(), hostname)
	// check balacklist
	if conn.checkRBL(hostname) {
		log.Warnf("%s: known bad actor: '%s'\n", conn.showClient(), hostname)
		conn.send(smtp.STATUSNOACK, "flagged in reverse black list")
		conn.close = true
		return
	}
	conn.hello = true
	conn.extended = extended
	conn.clientName = hostname
	conn.dataBuffer.Reset()
	log.Debugf("%s: welcoming name: '%s'\n", conn.showClient(), hostname)
	// check if startls done
	_, istls := conn.conn.(*tls.Conn)
	capabilities := []string{}
	if extended {
		capabilities = append(capabilities, "PIPELINING", "8BITMIME")
		if !istls && conn.tlsConfig != nil {
			capabilities = append(capabilities, "STARTTLS")
		}
		domains := strings.Split(conn.clientName, ".")
		genericdomain := strings.Join(domains[len(domains)-2:], ".")
		if utils.ContainsString(noBdatDomains, genericdomain) < 0 {
			capabilities = append(capabilities, "CHUNKING")

		}
	}
	conn.send(smtp.STATUSOK, fmt.Sprintf("welcome %s", hostname), capabilities...)
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
	tcpconn := conn.conn.RemoteAddr().(*net.TCPAddr)
	if !tcpconn.IP.IsLoopback() {
		log.Debugf("%s: localhost connection not on loopback\n", conn.showClient())
		return false
	}
	return true
}

func (conn *Conn) noop(params string) {
	if strings.EqualFold(params, Healthcheck) {
		conn.check = true
	}
	conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) rset() {
	log.Debugf("%s: reseting status", conn.showClient())
	conn.mailFrom = nil
	conn.rcptTo = make([]address.MailAddress, 0)
	conn.dataBuffer.Reset()
	conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) starttls() {
	_, isTLS := conn.conn.(*tls.Conn)
	if isTLS {
		log.Warnf("%s: connection already tls", conn.showClient())
		conn.send(smtp.STATUSNOTLS, "connection already tls")
		return
	}
	if conn.tlsConfig == nil {
		log.Errorf("%s: starttls and no tls configuration", conn.showClient())
		conn.send(smtp.STATUSNOTLS, "tls not supported")
		return
	}
	log.Debugf("%s: switching to tls", conn.showClient())
	// ready for TLS
	conn.send(smtp.STATUSRDY, "ready to discuss privately")
	err := conn.writeall()
	if err != nil {
		log.Errorf("%s: failed to ack starttls %s", conn.showClient(), err.Error())
		return
	}
	tlsConn := tls.Server(conn.conn, conn.tlsConfig)
	log.Debugf("%s: tls handshake", conn.showClient())
	err = tlsConn.Handshake()
	if err != nil {
		log.Errorf("%s: failed to start tls connection %s", conn.showClient(), err.Error())
		conn.send(smtp.STATUSNOPOL, "tls handshake error")
		return
	}
	log.Debugf("%s: starttls complete (%s)", conn.showClient(), tlsinfo.TlsInfo(tlsConn))
	// reset state
	conn.hello = false
	conn.conn = tlsConn
	conn.mailFrom = nil
	conn.rcptTo = make([]address.MailAddress, 0)
	conn.dataBuffer.Reset()
}

func (conn *Conn) mailfrom(param string) {
	ma, err := address.NewMailAddress(param)
	if err != nil {
		log.Errorf("%s: mail from %s not valid", conn.showClient(), ma)
		conn.send(smtp.STATUSNOPOL, fmt.Sprintf("from %s nok", param))
		return
	}
	log.Debugf("%s: mail from %s", conn.showClient(), ma)
	conn.mailFrom = ma
	conn.rcptTo = make([]address.MailAddress, 0)
	conn.send(smtp.STATUSOK, fmt.Sprintf("from %s ok", param))
}

func (conn *Conn) rcptto(param string) {
	ma, err := address.NewMailAddress(param)
	if err != nil {
		log.Errorf("%s: recipient %s not valid: %s", conn.showClient(), param, err)
		conn.send(smtp.STATUSNOPOL, fmt.Sprintf("recipient %s nok", param))
		return
	}
	acceptedDomain := false
	for _, domain := range conn.domains {
		if strings.EqualFold(strings.TrimRight(ma.Domain, "."), strings.TrimRight(domain, ".")) {
			acceptedDomain = true
			break
		}
	}
	if !acceptedDomain {
		log.Errorf("%s: recipient %s not in a valid domain", conn.showClient(), ma.String())
		conn.send(smtp.STATUSNOPOL, fmt.Sprintf("recipient %s domain nok", param))
		return
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
	conn.send(smtp.STATUSOK, fmt.Sprintf("recipient %s ok", param))
}

func (conn *Conn) getTrace() string {
	// get information on the remove address
	remoteaddr := conn.clientName
	tcpaddr := conn.conn.RemoteAddr().(*net.TCPAddr)
	remoteaddr += fmt.Sprintf(" (%s)", tcpaddr.IP.String())

	// get information on the remte address
	localaddr := conn.ServerName
	tcpaddr = conn.conn.LocalAddr().(*net.TCPAddr)
	localaddr += fmt.Sprintf(" (%s)", tcpaddr.IP.String())

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

func (conn *Conn) data() {
	// check before sending
	conn.checkdata()

	// accept to recieve data
	conn.send(smtp.STATUSACT, "send the message")

	// reset the data buffer
	conn.dataBuffer.Reset()

	// start of data transmission
	conn.dataStart = time.Now().UnixNano()

	// read from input
	err := conn.readdata()
	if err != nil {
		log.Infof("%s: %s\n", conn.showClient(), err.Error())
	}

	// if empty body return
	if conn.dataBuffer.Len() == 0 {
		log.Warnf("%s: message empty", conn.showClient())
		conn.send(smtp.STATUSFAIL, "empty message")
		return
	}

	// end of data transmission
	conn.dataFinish = time.Now().UnixNano()

	// save to storage
	msg := message.Message{
		//Id:   uuid.NewString(),
		Id:   shortuuid.New(),
		From: conn.mailFrom,
		To:   conn.rcptTo,
		Data: conn.dataBuffer.Bytes(),
	}

	// clear databuffer
	conn.dataBuffer.Reset()

	// send the message
	conn.sendmessage(msg)
}

func (conn *Conn) binarydata(params string) {
	// check before sending
	conn.checkdata()

	//check bdata params
	if !BdataParams.MatchString(params) {
		log.Errorf("%s: message empty", conn.showClient())
		conn.send(smtp.STATUSERROR, "syntax error")
		return
	}

	// parse parameters
	parts := strings.Split(params, " ")
	datalen, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		log.Errorf("%s: invalid length", conn.showClient())
		conn.send(smtp.STATUSERROR, "invalid length")
		return
	}
	last := len(parts) == 2

	// info
	log.Debugf("%s: expected %d bytes (last:%v)", conn.showClient(), datalen, last)

	// binary data recieves directly
	if conn.dataStart == 0 {
		conn.dataStart = time.Now().UnixNano()
	}

	if datalen > 0 {

		unread := conn.dataBuffer.Len()

		// copy the data to the data buffer
		_, err := io.CopyN(conn.dataBuffer, conn.conn, datalen)
		if err != nil {
			log.Errorf("%s: issue while reading: %s", conn.showClient(), err.Error())
			disablebdat(conn.clientName)
			conn.send(smtp.STATUSFAIL, "issue while reading binary data")
			conn.dataBuffer.Truncate(unread)
			return
		}
	}

	// if not the last chunk continue as usual
	if !last {
		conn.send(smtp.STATUSOK, fmt.Sprintf("%s: recieved %d bytes", conn.showClient(), datalen))
		return
	}

	conn.dataFinish = time.Now().UnixNano()

	// save to storage
	msg := message.Message{
		//Id:   uuid.NewString(),
		Id:   shortuuid.New(),
		From: conn.mailFrom,
		To:   conn.rcptTo,
		Data: conn.dataBuffer.Bytes(),
	}

	// clear databuffer
	conn.dataBuffer.Reset()

	// send the message
	conn.sendmessage(msg)
}

func disablebdat(server string) {
	domains := strings.Split(server, ".")
	genericdomain := strings.Join(domains[len(domains)-2:], ".")
	log.Warnf("disabling binary data for: %s", genericdomain)
	noBdatDomains = append(noBdatDomains, genericdomain)
}

func (conn *Conn) checkdata() {
	log.Debugf("%s: check before recieving data", conn.showClient())

	// check if from and to ar there
	if len(conn.rcptTo) == 0 || conn.mailFrom == nil {
		// not ready to recieve a mail - i don't know where it goes!
		log.Errorf("%s: refusing data without 'from' and 'to'", conn.showClient())
		conn.send(smtp.STATUSBADSEC, "please tell me from/to before sending a message")
		return
	}

	// warn if sending over clear text
	_, isTLS := conn.conn.(*tls.Conn)
	if !isTLS {
		log.Warnf("%s: recieving message over clear text", conn.showClient())
	}
}

func (conn *Conn) sendmessage(msg message.Message) {
	log.Infof("%s: message %s (%d bytes) to %v", conn.showClient(), msg.Id, len(msg.Data), msg.Recipients())

	accept, _ := conn.spfCheck("", 0)
	if !accept && !msg.Signed() {
		log.Warnf("%s: message %s is not signed and refused by SPF checks", conn.showClient(), msg.Id)
		conn.send(smtp.STATUSNOPOL, "spf failed")
		conn.close = true
		return
	}

	msgID, reject, err := conn.processor.Handle(msg)

	if err != nil {
		log.Errorf("%s:%s: error handling message: %s", conn.showClient(), msgID, err.Error())
		if reject {
			conn.send(smtp.STATUSNOPOL, "mail rejected")
			return
		}
		conn.send(smtp.STATUSTMPER, "could not handle message")
		return
	}

	elapsed := float64(conn.dataFinish-conn.dataStart) / 1000000000.
	size := len(msg.Data)
	speed := float64(size) * 100 / float64(elapsed) / 1024

	log.Infof("%s: message %s recieved - %d bytes in %.3f secs (%.2f KBps)", conn.showClient(), msg.Id, size, elapsed, speed)
	conn.send(smtp.STATUSOK, fmt.Sprintf("recieved %d bytes in %.3f secs (%.2f KBps)", size, elapsed, speed))
}

func (conn *Conn) readdata() error {
	// get a buffer reader
	reader := bufio.NewReader(conn.conn)

	// get a text proto reader
	tp := textproto.NewReader(reader)

	// get trace information
	trace := conn.getTrace()
	log.Debugf("%s: trace: %s", conn.showClient(), trace)
	conn.dataBuffer.WriteString(trace)
	conn.dataBuffer.WriteString("\r\n")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			log.Infof("%s: %s\n", conn.showClient(), err.Error())
			return fmt.Errorf("cannot read")
		}
		log.Tracef("%s < %s\n", conn.showClient(), line)
		if line == "." {
			break
		}
		conn.dataBuffer.WriteString(line)
		conn.dataBuffer.WriteString("\r\n")
	}
	return nil
}

func (conn *Conn) quit() {
	log.Debugf("%s: goodbye", conn.showClient())
	conn.send(smtp.STATUSBYE, "goodbye")
	conn.close = true
}

func (conn *Conn) parse(command string) (string, string, error) {
	if !IsAsciiPrintable(command) {
		conn.send(smtp.STATUSBYE, "unacceptable characters")
		conn.close = true
		return "", "", fmt.Errorf("command contains non ascii printable characters")
	}
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
