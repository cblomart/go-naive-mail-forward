package client

import (
	"bufio"
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/smtp"
	"cblomart/go-naive-mail-forward/tlsinfo"
	"crypto/tls"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"

	log "cblomart/go-naive-mail-forward/logger"
)

var (
	Trace = false
	Debug = false
)

type SmtpClient struct {
	conn         net.Conn
	LocalPort    string
	Relay        string
	Domains      []string
	Hostname     string
	lock         *sync.Mutex
	Connected    bool
	LastSent     time.Time
	TlsSupported bool
}

func (c *SmtpClient) Connect() error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:25", c.Relay))
	if err != nil {
		return err
	}
	// get local port
	parts := strings.Split(conn.LocalAddr().String(), ":")
	c.LocalPort = parts[len(parts)-1]
	log.Debugf("%s:%s: connected", c.LocalPort, c.Relay)
	c.conn = conn
	// create the lock if empty as connection is established
	if c.lock == nil {
		c.lock = &sync.Mutex{}
	}
	// lock while waiting aknownledgement from server
	c.lock.Lock()
	defer c.lock.Unlock()
	// read ack from server
	_, err = c.readLine(smtp.STATUSRDY)
	if err != nil {
		// #nosec G104 ignore quit
		c.Quit()
		return err
	}
	c.Connected = true
	return nil
}

func (c *SmtpClient) Close() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	log.Infof("disconnecting from %s", c.Relay)
	if c.conn != nil {
		c.Connected = false
		// #nosec G104 ignore quit
		c.Quit()
		return c.conn.Close()
	}
	return nil
}

func (c *SmtpClient) checkSmtpRespCode(expcode int, line string) (bool, error) {
	if fmt.Sprintf("%d", expcode) != line[:3] {
		return false, fmt.Errorf("unexpexted error code returned %d", expcode)
	}
	if line[3] == '-' {
		return true, nil
	}
	return false, nil
}

func (c *SmtpClient) sendCmd(command string) error {
	log.Tracef("%s:%s: > %s", c.LocalPort, c.Relay, command)
	_, err := fmt.Fprintf(c.conn, "%s\r\n", command)
	return err
}

func (c *SmtpClient) readLine(code int) (string, error) {
	// check welcome message from server
	// get a buffer reader
	reader := bufio.NewReader(c.conn)
	// get a text proto reader
	tp := textproto.NewReader(reader)
	var err error
	line := ""
	for {
		line, err = tp.ReadLine()
		if err != nil {
			return "", err
		}
		log.Tracef("%s:%s: < %s", c.LocalPort, c.Relay, line)
		more, err := c.checkSmtpRespCode(code, line)
		if err != nil {
			return "", err
		}
		if strings.ToUpper(line[4:]) == "STARTTLS" {
			c.TlsSupported = true
		}
		if !more {
			break
		}
	}
	return line, nil
}

func (c *SmtpClient) Quit() error {
	return c.sendCmd("QUIT")
}

func (c *SmtpClient) StartTLS() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	err := c.sendCmd("STARTTLS")
	if err != nil {
		return err
	}
	_, err = c.readLine(smtp.STATUSRDY)
	if err != nil {
		// #nosec G104 ignore quit
		c.Quit()
		return err
	}
	// build the tls connection
	log.Debugf("%s:%s: switching to tls", c.LocalPort, c.Relay)
	tlsConn := tls.Client(
		c.conn,
		&tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		},
	)
	log.Debugf("%s:%s: tls handshake", c.LocalPort, c.Relay)
	err = tlsConn.Handshake()
	if err != nil {
		return err
	}
	log.Debugf("%s:%s: starttls complete (%s)", c.LocalPort, c.Relay, tlsinfo.TlsInfo(tlsConn))
	c.conn = tlsConn
	return nil
}

func (c *SmtpClient) Helo() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	// try ehlo first
	err := c.sendCmd(fmt.Sprintf("EHLO %s", c.Hostname))
	if err != nil {
		return err
	}
	_, err = c.readLine(smtp.STATUSOK)
	if err == nil {
		return nil
	}
	// try helo next
	err = c.sendCmd(fmt.Sprintf("HELO %s", c.Hostname))
	if err != nil {
		return err
	}
	_, err = c.readLine(smtp.STATUSOK)
	if err != nil {
		// #nosec G104 ignore quit
		c.Quit()
		return err
	}
	return nil
}

func (c *SmtpClient) Noop() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	err := c.sendCmd("NOOP")
	if err != nil {
		return err
	}
	_, err = c.readLine(smtp.STATUSOK)
	if err != nil {
		// #nosec G104 ignore quit
		c.Quit()
		return err
	}
	return nil
}

func (c *SmtpClient) MailFrom(dest string) error {
	err := c.sendCmd(fmt.Sprintf("MAIL FROM:<%s>", dest))
	if err != nil {
		return err
	}
	_, err = c.readLine(smtp.STATUSOK)
	if err != nil {
		// #nosec G104 ignore quit
		c.Quit()
		return err
	}
	return nil
}

func (c *SmtpClient) RcptTo(dest string) error {
	err := c.sendCmd(fmt.Sprintf("RCPT TO:<%s>", dest))
	if err != nil {
		return err
	}
	_, err = c.readLine(smtp.STATUSOK)
	if err != nil {
		// #nosec G104 ignore quit
		c.Quit()
		return err
	}
	return nil
}

func (c *SmtpClient) Data(data string) error {
	_, isTls := c.conn.(*tls.Conn)
	if !isTls {
		log.Warnf("%s:%s: sending message over clear text", c.LocalPort, c.Relay)
	}
	err := c.sendCmd("DATA")
	if err != nil {
		return err
	}
	_, err = c.readLine(smtp.STATUSACT)
	if err != nil {
		// #nosec G104 ignore quit
		c.Quit()
		return err
	}
	// sending data
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		log.Tracef("%s:%s: > %s", c.LocalPort, c.Relay, line)
		_, err := fmt.Fprintf(c.conn, "%s\r\n", line)
		if err != nil {
			return err
		}
	}
	log.Tracef("%s:%s: > .", c.LocalPort, c.Relay)
	_, err = fmt.Fprint(c.conn, ".\r\n")
	if err != nil {
		return err
	}
	_, err = c.readLine(smtp.STATUSOK)
	if err != nil {
		// #nosec G104 ignore quit
		c.Quit()
		return err
	}
	return nil
}

func (c *SmtpClient) SendMessage(msg message.Message) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	log.Debugf("%s:%s: message %s sending", c.LocalPort, c.Relay, msg.Id)
	// sent mail from
	err := c.MailFrom(msg.From.String())
	if err != nil {
		log.Errorf("%s:%s:%s: %s", c.LocalPort, c.Relay, msg.Id, err.Error())
		return err
	}
	// get recipients for domains
	tos := msg.ToDomains(c.Domains)
	if len(tos) == 0 {
		log.Infof("%s:%s:%s no recipient for the message in %s", c.LocalPort, c.Relay, msg.Id, strings.Join(c.Domains, ", "))
		return fmt.Errorf("no recipients in domains")
	}
	// prepare relay for fqdn check
	for _, to := range tos {
		log.Debugf("%s:%s:%s adding recipient %s", c.LocalPort, c.Relay, msg.Id, to)
		err = c.RcptTo(to)
		if err != nil {
			log.Infof("%s:%s:%s %s", c.LocalPort, c.Relay, msg.Id, err.Error())
			continue
		}
	}
	err = c.Data(msg.Data)
	if err != nil {
		log.Infof("%s:%s:%s %s", c.LocalPort, c.Relay, msg.Id, err.Error())
		return err
	}
	c.LastSent = time.Now()
	return nil
}

func (c *SmtpClient) StartSession() error {
	// connect to server
	err := c.Connect()
	if err != nil {
		log.Infof("could not connect to mx %s", c.Hostname)
		return err
	}
	// present ourselves
	err = c.Helo()
	if err != nil {
		log.Infof("not welcomed by mx %s", c.Hostname)
		return err
	}
	// handle tls
	if c.TlsSupported {
		err = c.StartTLS()
		if err != nil {
			log.Infof("tls fail for mx %s", c.Hostname)
			return err
		}
		// re hello
		err = c.Helo()
		if err != nil {
			log.Infof("not welcomed by mx %s", c.Hostname)
			return err
		}
	}
	return nil
}
