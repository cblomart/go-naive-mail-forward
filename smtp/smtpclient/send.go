package smtpclient

import (
	"bufio"
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/smtp"
	"cblomart/go-naive-mail-forward/tlsinfo"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

var (
	Trace       = false
	Debug       = false
	TlsInsecure = true
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
	if Debug {
		log.Printf("client - %s:%s: connected", c.LocalPort, c.Relay)
	}
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
	log.Printf("client - disconnecting from %s", c.Relay)
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
	if Trace {
		log.Printf("client - %s:%s: > %s", c.LocalPort, c.Relay, command)
	}
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
		if Trace {
			log.Printf("client - %s:%s: < %s", c.LocalPort, c.Relay, line)
		}
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
	if Debug {
		log.Printf("client - %s:%s: switching to tls", c.LocalPort, c.Relay)
	}
	tlsConn := tls.Client(
		c.conn,
		&tls.Config{
			InsecureSkipVerify: TlsInsecure,
		},
	)
	if Debug {
		log.Printf("client - %s:%s: tls handshake", c.LocalPort, c.Relay)
	}
	err = tlsConn.Handshake()
	if err != nil {
		return err
	}
	if Debug {
		log.Printf("client - %s:%s: starttls complete (%s)", c.LocalPort, c.Relay, tlsinfo.TlsInfo(tlsConn))
	}
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
		log.Printf("client - %s:%s: sending message over clear text!", c.LocalPort, c.Relay)
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
		if Debug {
			log.Printf("client - %s:%s: > %s", c.LocalPort, c.Relay, line)
		}
		_, err := fmt.Fprintf(c.conn, "%s\r\n", line)
		if err != nil {
			return err
		}
	}
	if Debug {
		log.Printf("client - %s:%s: > .", c.LocalPort, c.Relay)
	}
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
	if Debug {
		log.Printf("client - %s:%s: message %s sending", c.LocalPort, c.Relay, msg.Id)
	}
	// sent mail from
	err := c.MailFrom(msg.From.String())
	if err != nil {
		log.Printf("client - %s:%s:%s: %s", c.LocalPort, c.Relay, msg.Id, err.Error())
		return err
	}
	// get recipients for domains
	tos := msg.ToDomains(c.Domains)
	if len(tos) == 0 {
		log.Printf("client - %s:%s:%s no recipient for the message in %s", c.LocalPort, c.Relay, msg.Id, strings.Join(c.Domains, ", "))
		return fmt.Errorf("no recipients in domains")
	}
	// prepare relay for fqdn check
	for _, to := range tos {
		if Debug {
			log.Printf("client - %s:%s:%s adding recipient %s", c.LocalPort, c.Relay, msg.Id, to)
		}
		err = c.RcptTo(to)
		if err != nil {
			log.Printf("client - %s:%s:%s %s", c.LocalPort, c.Relay, msg.Id, err.Error())
			continue
		}
	}
	err = c.Data(msg.Data)
	if err != nil {
		log.Printf("client - %s:%s:%s %s", c.LocalPort, c.Relay, msg.Id, err.Error())
		return err
	}
	c.LastSent = time.Now()
	return nil
}

func SendMessages(hostname string, domain string, msgs []message.Message, debug bool) ([]string, error) {
	// lookup first mx for domain
	// mail exchangers must be known
	mxs, err := net.LookupMX(domain)
	if err != nil {
		return nil, err
	}
	// create smtp client
	client := &SmtpClient{
		Relay:    mxs[0].Host,
		Domains:  []string{domain},
		Hostname: hostname,
	}
	// connect to server
	err = client.Connect()
	if err != nil {
		return nil, err
	}
	// close connection on exit
	defer client.Close()
	// hello server
	err = client.Helo()
	if err != nil {
		return nil, err
	}
	// loop over the messages
	// recover ids of sent messages
	ids := make([]string, 0)
	for _, msg := range msgs {
		err := client.SendMessage(msg)
		if err != nil {
			log.Printf("client - %s:%s:%s %s", client.LocalPort, client.Relay, msg.Id, err.Error())
			continue
		}
		// message sent :)
		ids = append(ids, msg.Id)
	}
	return ids, nil
}
