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
	"strconv"
	"strings"
	"sync"
	"time"

	log "cblomart/go-naive-mail-forward/logger"

	"github.com/google/uuid"
)

const (
	Localhost       = "localhost"
	Healthcheck     = "healthcheck"
	timeoutDuration = 100 * time.Millisecond
)

var (
	Trace        = false
	Debug        = false
	DomainMatch  = regexp.MustCompile(`(?i)^([a-z0-9-]{1,63}\.)+[a-z]{2,63}\.?$`)
	BdataParams  = regexp.MustCompile(`(?i)^[0-9]+( +LAST)?$`)
	clientId     = 0
	clientIdLock = sync.RWMutex{}
	needHelo     = []string{"RSET", "MAIL FROM", "RCPT TO", "DATA", "BDAT", "STARTTLS"}
	noPipeline   = []string{"EHLO", "HELO", "QUIT", "STARTTLS", "NOOP", "DATA", "BDAT", "DEBUG", "TRACE"}
)

//Conn is a smtp client connection
type Conn struct {
	id             int
	conn           net.Conn
	hello          bool
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
	sendBuffer     []Response
	recieveBuffer  []byte
	recieveBufferN int
	dataBuffer     []byte
	dataStart      int64
	dataFinish     int64
}

type Response struct {
	Code    int
	Message string
	Extra   []string
}

func (r *Response) String() string {
	return fmt.Sprintf("%d %s (+%s)", r.Code, r.Message, strings.Join(r.Extra, ","))
}

func HandleSmtpConn(conn net.Conn, serverName string, processor *process.Process, domains []string, dnsbl string, keyfile string, certfile string, insecuretls bool, nospf bool) {
	smtpConn := NewSmtpConn(conn, serverName, processor, domains, dnsbl, keyfile, certfile, insecuretls, nospf)
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
		id:            id,
		conn:          conn,
		hello:         false,
		clientName:    "",
		ServerName:    serverName,
		mailFrom:      nil,
		rcptTo:        make([]address.MailAddress, 0),
		processor:     processor,
		domains:       domains,
		tlsConfig:     tlsConfig,
		dnsbl:         strings.Split(dnsbl, ","),
		nospf:         nospf,
		recieveBuffer: make([]byte, 1024),
		dataBuffer:    []byte{},
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
	conn.ack()
	_, err := conn.processBuffer()
	if err != nil {
		log.Errorf("%s: %s\n", conn.showClient(), err.Error())
		return
	}
	// start the command response session
	for {
		// read lines from input
		lines, err := conn.readlines()
		if err != nil {
			// log connection drops as debug
			if err.Error() != "connection dropped" {
				log.Errorf("%s: %s\n", conn.showClient(), err.Error())
			} else {
				log.Debugf("%s: %s\n", conn.showClient(), err.Error())
			}
			break
		}
		stop := false
		l := len(lines) - 1
		for i, line := range lines {
			stop = conn.processLine(line, i == l)
			if stop {
				break
			}
		}
		if stop {
			break
		}
	}
}

func (conn *Conn) processLine(line string, last bool) bool {
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
	if utils.ContainsString(noPipeline, cmd) >= 0 || last {
		quit, err := conn.processBuffer()
		if err != nil {
			log.Errorf("%s: %s\n", conn.showClient(), err.Error())
		}
		return quit
	}
	return false
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
	conn.sendBuffer = append(conn.sendBuffer, resp)
}

func (conn *Conn) processBuffer() (bool, error) {
	// init the globalstatus
	globalstatus := 0
	// send each responses
	for _, r := range conn.sendBuffer {
		// send extra answers
		if len(r.Extra) > 0 {
			for _, e := range r.Extra {
				log.Tracef("%s > %d-%s\n", conn.showClient(), r.Code, e)
				_, err := fmt.Fprintf(conn.conn, "%d-%s\r\n", r.Code, e)
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
	return quit, nil
}

func (conn *Conn) ack() {
	// be sure the send buffer is empty
	conn.sendBuffer = []Response{}
	// hello client
	conn.send(smtp.STATUSRDY, fmt.Sprintf("%s Go Naive Mail Forwarder", conn.ServerName))
}

func (conn *Conn) unknown(command string) {
	log.Warnf("%s: syntax error: '%s'\n", conn.showClient(), command)
	conn.send(smtp.STATUSERROR, "syntax error")
}

func (conn *Conn) helo(hostname string, extended bool) {
	log.Debugf("%s: checking hostname: %s", conn.showClient(), hostname)
	if !conn.hostnameChecks(hostname) {
		conn.send(smtp.STATUSNOACK, "malformed hostname")
		return
	}
	log.Debugf("%s: checking if legit localhost: %s", conn.showClient(), hostname)
	// check that localhost connections comes from localhost
	if strings.EqualFold(hostname, Localhost) && !conn.ipIsLocal() {
		log.Warnf("%s: localhost but not local ip: '%s'\n", conn.showClient(), hostname)
		conn.send(smtp.STATUSNOACK, "invalid localhost handshake")
		return
	}
	log.Debugf("%s: checking RBL: %s", conn.showClient(), hostname)
	// check balacklist
	if conn.checkRBL(hostname) {
		log.Warnf("%s: known bad actor: '%s'\n", conn.showClient(), hostname)
		conn.send(smtp.STATUSNOACK, "flagged in reverse black list")
		return
	}
	conn.hello = true
	conn.extended = extended
	conn.clientName = hostname
	log.Debugf("%s: welcoming name: '%s'\n", conn.showClient(), hostname)
	// check if startls done
	_, istls := conn.conn.(*tls.Conn)
	capabilities := []string{}
	if extended {
		capabilities = append(capabilities, "PIPELINING", "8BITMIME", "CHUNKING")
		if !istls && conn.tlsConfig != nil {
			capabilities = append(capabilities, "STARTTLS")
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
	_, err := conn.processBuffer()
	if err != nil {
		log.Infof("%s: could not respond to client %s", conn.showClient(), err.Error())
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

func (conn *Conn) data() {
	// check before sending
	conn.checkdata()

	// accept to recieve data
	conn.send(smtp.STATUSACT, "send the message")

	// process send buffer (pipelining)
	_, err := conn.processBuffer()
	if err != nil {
		log.Errorf("%s: %s\n", conn.showClient(), err.Error())
		return
	}

	// start of data transmission
	conn.dataStart = time.Now().Unix()

	// read from input
	data, err := conn.readdata()
	if err != nil {
		log.Infof("%s: %s\n", conn.showClient(), err.Error())
	}

	// if empty body return
	if len(data) == 0 {
		log.Warnf("%s: message empty", conn.showClient())
		conn.send(smtp.STATUSFAIL, "empty message")
		return
	}

	// end of data transmission
	conn.dataFinish = time.Now().Unix()

	// save to storage
	msg := message.Message{
		Id:   uuid.NewString(),
		From: conn.mailFrom,
		To:   conn.rcptTo,
		Data: data,
	}

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
	datalen, err := strconv.Atoi(parts[0])
	if err != nil {
		log.Errorf("%s: invalid length", conn.showClient())
		conn.send(smtp.STATUSERROR, "invalid length")
		return
	}
	last := len(parts) == 2

	// process send buffer (pipelining)
	_, err = conn.processBuffer()
	if err != nil {
		log.Errorf("%s: %s\n", conn.showClient(), err.Error())
		return
	}

	// binary data recieves directly
	conn.dataStart = time.Now().Unix()

	if datalen > 0 {
		// declare a buffer of the right length
		buffer := make([]byte, datalen)

		// read the data
		_, err = io.ReadFull(conn.conn, buffer)
		if err != nil {
			log.Errorf("%s: issue while reading", conn.showClient())
			conn.send(smtp.STATUSTMPER, "issue while reading")
			return
		}
		log.Infof("%s: recieved %d bytes", conn.showClient(), len(buffer))

		// append to data buffer
		conn.dataBuffer = append(conn.dataBuffer, buffer...)
	}

	// if not the last chunk continue as usual
	if !last {
		conn.send(smtp.STATUSOK, fmt.Sprintf("%s: recieved %d bytes", conn.showClient(), datalen))
		return
	}

	conn.dataFinish = time.Now().Unix()

	// save to storage
	msg := message.Message{
		Id:   uuid.NewString(),
		From: conn.mailFrom,
		To:   conn.rcptTo,
		Data: string(conn.dataBuffer),
	}

	// clear databuffer
	conn.dataBuffer = []byte{}

	// send the message
	conn.sendmessage(msg)
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

	log.Infof("%s: message %s recieved", conn.showClient(), msg.Id)

	elapsed := int(conn.dataFinish - conn.dataStart)
	size := len(msg.Data)
	speed := size * 100 / elapsed / 1024
	speedtxt := fmt.Sprintf("%d", speed)

	conn.send(smtp.STATUSOK, fmt.Sprintf("recieved %d bytes in %d secs (%s.%s KBps)", size, elapsed, speedtxt[:len(speedtxt)-3], speedtxt[len(speedtxt)-3:]))
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

func (conn *Conn) quit() {
	log.Debugf("%s: goodbye", conn.showClient())
	conn.send(smtp.STATUSBYE, "goodbye")
}

func (conn *Conn) parse(command string) (string, string, error) {
	log.Tracef("%s < %s\n", conn.showClient(), command)
	if !IsAsciiPrintable(command) {
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

func (conn *Conn) readlines() ([]string, error) {
	defer conn.conn.SetReadDeadline(time.Time{})
	// make the buffer of line read
	lines := []string{}

	// read byte per byte
	for {
		// set the time out for this byte read
		// #nosec G104
		conn.conn.SetReadDeadline(time.Now().Add(timeoutDuration))

		// buffer for byte to read
		b := make([]byte, 1)

		// read from connection
		n, err := conn.conn.Read(b)

		if err == io.EOF {
			if len(lines) > 0 {
				return lines, nil
			}
			return nil, err
		}

		if n == 0 {
			if len(lines) > 0 {
				return lines, nil
			}
			continue
		}

		// add the line if recieve new line
		if b[0] == '\n' {
			lines = append(lines, string(conn.recieveBuffer[:conn.recieveBufferN]))
			conn.recieveBufferN = 0
			continue
		}

		// ignore line feeds
		if b[0] == '\r' {
			continue
		}

		// replace tab by space
		if b[0] == '\t' {
			b[0] = ' '
		}

		// send an error if character is not ascii
		if !IsAscii(b[0]) {
			return nil, fmt.Errorf("recievied non ascii input '%d'", b[0])
		}

		// add the read character to the buffer
		conn.recieveBuffer[conn.recieveBufferN] = b[0]
		conn.recieveBufferN++
	}
}
