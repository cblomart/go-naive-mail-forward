package smtpserver

import (
	"bufio"
	"cblomart/go-naive-mail-forward/address"
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/process"
	"cblomart/go-naive-mail-forward/smtp"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"regexp"
	"strings"
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
}

var DomainMatch = regexp.MustCompile("^([a-z0-9-]{1,63}\\.)+[a-z]{2,63}\\.?$")

func HandleSmtpConn(tcpConn net.Conn, serverName string, processor *process.Process, domains []string, debug bool) {
	smtpConn := NewSmtpConn(tcpConn, serverName, processor, domains, debug)
	defer smtpConn.Close()
	smtpConn.ProcessMessages()
}

func NewSmtpConn(conn net.Conn, serverName string, processor *process.Process, domains []string, debug bool) *Conn {
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
	}
}

func (conn *Conn) Close() error {
	return conn.conn.Close()
}

func (conn *Conn) ProcessMessages() {
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
	if len(conn.clientName) == 0 {
		return conn.conn.RemoteAddr().String()
	}
	infos := strings.Split(conn.conn.RemoteAddr().String(), ":")
	return fmt.Sprintf("%s:%s", conn.clientName, infos[len(infos)-1])
}

func (conn *Conn) send(status int, message string) error {
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

func (conn *Conn) helo(hostname string) (bool, error) {
	// user lowercased hostname
	hostname = strings.ToLower(hostname)
	if !DomainMatch.MatchString(hostname) {
		// regex failed
		log.Printf("server - %s: failed to verify: '%s'\n", conn.showClient(), hostname)
		return true, conn.send(smtp.STATUSNOACK, "cannot continue")
	}
	if strings.ToUpper(strings.TrimRight(conn.ServerName, ".")) == strings.ToUpper(strings.TrimRight(hostname, ".")) {
		// greeted with my name... funny
		log.Printf("server - %s: greeting a doppleganger: '%s'\n", conn.showClient(), hostname)
		return true, conn.send(smtp.STATUSNOACK, "cannot continue")
	}
	conn.hello = true
	conn.clientName = hostname
	log.Printf("server - %s: accepting name: '%s'\n", conn.showClient(), hostname)
	return false, conn.send(smtp.STATUSOK, fmt.Sprintf("welcome %s", hostname))
}

func (conn *Conn) noop() error {
	return conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) rset() error {
	log.Printf("server - %s: reseting smtp.STATUS", conn.showClient())
	conn.mailFrom = nil
	conn.rcptTo = make([]address.MailAddress, 0)
	return conn.send(smtp.STATUSOK, "ok")
}

func (conn *Conn) mailfrom(param string) error {
	ma, err := address.NewMailAddress(param)
	if err != nil {
		log.Printf("server - %s: mail from %s not valid", conn.showClient(), ma)
		return conn.send(smtp.STATUSNOPOL, "bad mail address")
	}
	log.Printf("server - %s: mail from %s", conn.showClient(), ma)
	conn.mailFrom = ma
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
	log.Printf("server - %s: sending to %s", conn.showClient(), strings.Join(addresses, ";"))
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
	msgId, err := conn.processor.Add(msg)
	if err != nil {
		log.Printf("server - %s: error saving message: %s", conn.showClient(), err.Error())
		return conn.send(smtp.STATUSNOSTOR, "cannot save message")
	}
	log.Printf("server - %s: recieved mail %s (%d bytes)", conn.showClient(), msgId, sb.Len())
	return conn.send(smtp.STATUSOK, "recieved 5/5")
}

func (conn *Conn) quit() error {
	log.Printf("server - %s: goodbye", conn.showClient())
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
