package smtp

import (
	"bufio"
	"cblomart/go-naive-mail-forward/address"
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/store"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"regexp"
	"strings"
)

const (
	STATUSRDY    = 220
	STATUSBYE    = 221
	STATUSOK     = 250
	STATUSACT    = 354
	STATUSTMPER  = 451
	STATUSERROR  = 500
	STATUSNOTIMP = 502
	STATUSBADSEC = 503
	STATUSNOACK  = 521
	STATUSNOPOL  = 550
	STATUSNOSTOR = 552
)

//SmtpConn is a smtp client connection
type SmtpConn struct {
	conn       net.Conn
	hello      bool
	clientName string
	ServerName string
	Debug      bool
	mailFrom   *address.MailAddress
	rcptTo     []address.MailAddress
	msgStore   store.Store
	domains    []string
}

var DomainMatch = regexp.MustCompile("^([a-z0-9-]{1,63}\\.)+[a-z]{2,63}\\.?$")

func HandleSmtpConn(tcpConn net.Conn, serverName string, store store.Store, domains []string, debug bool) {
	smtpConn := NewSmtpConn(tcpConn, serverName, store, domains, debug)
	defer smtpConn.Close()
	log.Printf("Processing mails from domains: %s", strings.Join(domains, ", "))
	smtpConn.ProcessMessages()
}

func NewSmtpConn(conn net.Conn, serverName string, store store.Store, domains []string, debut bool) *SmtpConn {
	return &SmtpConn{
		conn:       conn,
		hello:      false,
		clientName: "",
		ServerName: "",
		Debug:      false,
		mailFrom:   nil,
		rcptTo:     make([]address.MailAddress, 0),
		msgStore:   store,
		domains:    domains,
	}
}

func (conn *SmtpConn) Close() error {
	return conn.conn.Close()
}

func (conn *SmtpConn) ProcessMessages() {
	log.Printf("%s: a new contender has arrived\n", conn.showClient())
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
			quit, nerr := conn.helo(params)
			if nerr != nil || quit {
				return
			}
			err = nerr
		case "NOOP":
			err = conn.noop()
		case "RSET":
			if !conn.hello {
				log.Printf("server - %s: reset without hello\n", conn.showClient())
				err = conn.send(STATUSBADSEC, "no hello")
				return
			}
			err = conn.rset()
		case "MAIL FROM":
			if !conn.hello {
				log.Printf("server - %s: recipient without hello\n", conn.showClient())
				err = conn.send(STATUSBADSEC, "no hello")
				return
			}
			err = conn.mailfrom(params)
		case "RCPT TO":
			if !conn.hello {
				log.Printf("server - %s: recipient without hello\n", conn.showClient())
				err = conn.send(STATUSBADSEC, "no hello")
				return
			}
			err = conn.rcptto(params)
		case "DATA":
			if !conn.hello {
				log.Printf("server - %s: recipient without hello\n", conn.showClient())
				err = conn.send(STATUSBADSEC, "no hello")
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

func (conn *SmtpConn) showClient() string {
	if len(conn.clientName) == 0 {
		return conn.conn.RemoteAddr().String()
	}
	infos := strings.Split(conn.conn.RemoteAddr().String(), ":")
	return fmt.Sprintf("%s:%s", conn.clientName, infos[len(infos)-1])
}

func (conn *SmtpConn) send(status int, message string) error {
	if conn.Debug {
		log.Printf("server - %s > %d %s\n", conn.showClient(), status, message)
	}
	_, err := fmt.Fprintf(conn.conn, "%d %s\r\n", status, message)
	return err
}

func (conn *SmtpConn) ack() error {
	return conn.send(STATUSRDY, fmt.Sprintf("%s Go Naive Mail Forwarder", conn.ServerName))
}

func (conn *SmtpConn) unknown(command string) error {
	log.Printf("server - %s: syntax error: '%s'\n", conn.showClient(), command)
	return conn.send(STATUSERROR, "syntax error")
}

func (conn *SmtpConn) helo(hostname string) (bool, error) {
	// user lowercased hostname
	hostname = strings.ToLower(hostname)
	if !DomainMatch.MatchString(hostname) {
		// regex failed
		log.Printf("server - %s: failed to verify: '%s'\n", conn.showClient(), hostname)
		return true, conn.send(STATUSNOACK, "cannot continue")
	}
	if strings.ToUpper(strings.TrimRight(conn.ServerName, ".")) == strings.ToUpper(strings.TrimRight(hostname, ".")) {
		// greeted with my name... funny
		log.Printf("server - %s: greeting a doppleganger: '%s'\n", conn.showClient(), hostname)
		return true, conn.send(STATUSNOACK, "cannot continue")
	}
	conn.hello = true
	conn.clientName = hostname
	log.Printf("server - %s: accepting name: '%s'\n", conn.showClient(), hostname)
	return false, conn.send(STATUSOK, fmt.Sprintf("welcome %s", hostname))
}

func (conn *SmtpConn) noop() error {
	return conn.send(STATUSOK, "ok")
}

func (conn *SmtpConn) rset() error {
	log.Printf("server - %s: reseting status", conn.showClient())
	conn.mailFrom = nil
	conn.rcptTo = make([]address.MailAddress, 0)
	return conn.send(STATUSOK, "ok")
}

func (conn *SmtpConn) mailfrom(param string) error {
	ma, err := address.NewMailAddress(param)
	if err != nil {
		log.Printf("server - %s: mail from %s not valid", conn.showClient(), ma)
		return conn.send(STATUSNOPOL, "bad mail address")
	}
	acceptedDomain := false
	for _, domain := range conn.domains {
		if strings.ToUpper(strings.TrimRight(ma.Domain, ".")) == strings.ToUpper(strings.TrimRight(domain, ".")) {
			acceptedDomain = true
			break
		}
	}
	if !acceptedDomain {
		log.Printf("server - %s: mail from %s not in a valid domain", conn.showClient(), ma)
		return conn.send(STATUSNOPOL, "unaccepted domain")
	}
	log.Printf("server - %s: mail from %s", conn.showClient(), ma)
	conn.mailFrom = ma
	return conn.send(STATUSOK, "ok")
}

func (conn *SmtpConn) rcptto(param string) error {
	ma, err := address.NewMailAddress(param)
	if err != nil {
		log.Printf("server - %s: mail to %s not valid", conn.showClient(), ma)
		return conn.send(STATUSNOPOL, "bad mail address")
	}
	conn.rcptTo = append(conn.rcptTo, *ma)
	addresses := make([]string, len(conn.rcptTo))
	for i, ma := range conn.rcptTo {
		addresses[i] = ma.String()
	}
	log.Printf("server - %s: sending to %s", conn.showClient(), strings.Join(addresses, ";"))
	return conn.send(STATUSOK, "ok")
}

func (conn *SmtpConn) data() error {
	if conn.Debug {
		log.Printf("server - %s: recieveing data", conn.showClient())
	}
	// check if from and to ar there
	if len(conn.rcptTo) == 0 || conn.mailFrom == nil {
		// not ready to recieve a mail - i don't know where it goes!
		log.Printf("server - %s: refusing data without 'from' and 'to'", conn.showClient())
		return conn.send(STATUSBADSEC, "please tell me from/to before sending a message")
	}
	err := conn.send(STATUSACT, "shoot")
	if err != nil {
		log.Printf("server - %s: %s\n", conn.showClient(), err.Error())
		return fmt.Errorf("Cannot read")
	}
	// get a buffer reader
	reader := bufio.NewReader(conn.conn)
	// get a text proto reader
	tp := textproto.NewReader(reader)
	var sb strings.Builder
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
	}
	// save to storage
	msg := message.Message{
		From: conn.mailFrom,
		To:   conn.rcptTo,
		Data: sb.String(),
	}
	msgId, err := conn.msgStore.Add(msg)
	if err != nil {
		log.Printf("server - %s: error saving message: %s", conn.showClient(), err.Error())
		return conn.send(STATUSNOSTOR, "cannot save message")
	}
	log.Printf("server - %s: recieved mail %s (%d bytes)", conn.showClient(), msgId, sb.Len())
	return conn.send(STATUSOK, "recieved 5/5")
}

func (conn *SmtpConn) quit() error {
	log.Printf("server - %s: goodbye", conn.showClient())
	return conn.send(STATUSBYE, "goodbye")
}

func (conn *SmtpConn) request() (string, string, error) {
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
