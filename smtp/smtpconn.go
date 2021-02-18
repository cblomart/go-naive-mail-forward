package smtp

import (
	"bufio"
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
	STATUSOK     = 220
	STATUSBYE    = 221
	STATUSDONE   = 250
	STATUSACT    = 354
	STATUSERROR  = 500
	STATUSNOTIMP = 502
	STATUSNOACK  = 521
	fqdnMatch    = "^([a-z0-9-]{1,63}\\.)+[a-z]{2,63}\\.?$"
)

//SmtpConn is a smtp client connection
type SmtpConn struct {
	conn       net.Conn
	hello      bool
	clientName string
	ServerName string
	Debug      bool
	from       string
	to         string
	msgStore   store.Store
}

func HandleSmtpConn(tcpConn net.Conn, serverName string, store store.Store, debug bool) {
	smtpConn := NewSmtpConn(tcpConn, store)
	smtpConn.ServerName = serverName
	smtpConn.Debug = debug
	defer smtpConn.Close()
	smtpConn.ProcessMessages()
}

func NewSmtpConn(conn net.Conn, store store.Store) *SmtpConn {
	return &SmtpConn{
		conn:       conn,
		hello:      false,
		clientName: "",
		ServerName: "",
		Debug:      false,
		msgStore:   store,
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
		log.Printf("%s: %s\n", conn.showClient(), err.Error())
		return
	}
	// start the command response session
	for {
		cmd, params, err := conn.request()
		if err != nil {
			log.Printf("%s: %s\n", conn.showClient(), err.Error())
			break
		}
		if conn.Debug {
			log.Printf("%s: got command: '%s'\n", conn.showClient(), cmd)
			log.Printf("%s: got params: '%s'\n", conn.showClient(), params)
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
				log.Printf("%s: reset without hello\n", conn.showClient())
				err = conn.send(STATUSNOACK, "no hello")
				return
			}
			err = conn.rset()
		case "MAIL FROM":
			if !conn.hello {
				log.Printf("%s: recipient without hello\n", conn.showClient())
				err = conn.send(STATUSNOACK, "no hello")
				return
			}
			err = conn.mailfrom(params)
		case "RCPT TO":
			if !conn.hello {
				log.Printf("%s: recipient without hello\n", conn.showClient())
				err = conn.send(STATUSNOACK, "no hello")
				return
			}
			err = conn.rcptto(params)
		case "DATA":
			if !conn.hello {
				log.Printf("%s: recipient without hello\n", conn.showClient())
				err = conn.send(STATUSNOACK, "no hello")
				return
			}
			err = conn.data()
		default:
			err = conn.unknown(cmd)
		}
		if err != nil {
			log.Printf("%s: %s\n", conn.showClient(), err.Error())
			break
		}
	}
}

func (conn *SmtpConn) showClient() string {
	if len(conn.clientName) > 0 {
		return conn.clientName
	}
	return conn.conn.RemoteAddr().String()
}

func (conn *SmtpConn) send(status int, message string) error {
	if conn.Debug {
		log.Printf("%s > %d %s\n", conn.showClient(), status, message)
	}
	_, err := fmt.Fprintf(conn.conn, "%d %s\r\n", status, message)
	return err
}

func (conn *SmtpConn) ack() error {
	return conn.send(STATUSOK, fmt.Sprintf("%s Go Naive Mail Forwarder", conn.ServerName))
}

func (conn *SmtpConn) unknown(command string) error {
	log.Printf("%s: syntax error: '%s'\n", conn.showClient(), command)
	return conn.send(STATUSERROR, "syntax error")
}

func (conn *SmtpConn) helo(hostname string) (bool, error) {
	// user lowercased hostname
	hostname = strings.ToLower(hostname)
	match, err := regexp.MatchString(fqdnMatch, hostname)
	if err != nil || !match {
		// regex failed
		log.Printf("%s: failed to verify: '%s'\n", conn.showClient(), hostname)
		return true, conn.send(STATUSNOACK, "cannot continue")
	}
	if strings.ToUpper(strings.TrimRight(conn.ServerName, ".")) == strings.ToUpper(strings.TrimRight(hostname, ".")) {
		// greeted with my name... funny
		log.Printf("%s: greeting a doppleganger: '%s'\n", conn.showClient(), hostname)
		return true, conn.send(STATUSNOACK, "cannot continue")
	}
	conn.hello = true
	conn.clientName = hostname
	if conn.Debug {
		log.Printf("%s: accepting name: '%s'\n", conn.showClient(), hostname)
	}
	return false, conn.send(STATUSOK, fmt.Sprintf("welcome %s", hostname))
}

func (conn *SmtpConn) noop() error {
	return conn.send(STATUSDONE, "ok")
}

func (conn *SmtpConn) rset() error {
	log.Printf("%s: reseting status", conn.showClient())
	conn.from = ""
	conn.to = ""
	return conn.send(STATUSDONE, "ok")
}

func (conn *SmtpConn) mailfrom(param string) error {
	param = strings.Trim(param, "<>")
	log.Printf("%s: mail from %s", conn.showClient(), param)
	conn.from = param
	return conn.send(STATUSDONE, "ok")
}

func (conn *SmtpConn) rcptto(param string) error {
	param = strings.Trim(param, "<>")
	log.Printf("%s: sending to %s", conn.showClient(), param)
	conn.to = param
	return conn.send(STATUSDONE, "ok")
}

func (conn *SmtpConn) data() error {
	log.Printf("%s: recieveing data", conn.showClient())
	return conn.send(STATUSNOTIMP, "not implemented sorry :)")
}

func (conn *SmtpConn) quit() error {
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
		log.Printf("%s: %s\n", conn.showClient(), err.Error())
		return "", "", fmt.Errorf("Cannot read")
	}
	if conn.Debug {
		log.Printf("%s < %s\n", conn.showClient(), command)
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
