package smtpclient

import (
	"bufio"
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/smtp"
	"fmt"
	"log"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

type SmtpClient struct {
	conn      net.Conn
	LocalPort string
	Relay     string
	Domains   []string
	Hostname  string
	Debug     bool
	lock      *sync.Mutex
	Connected bool
	LastSent  time.Time
}

func (c *SmtpClient) Connect() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:25", c.Relay))
	if err != nil {
		return err
	}
	// get local port
	parts := strings.Split(conn.LocalAddr().String(), ":")
	c.LocalPort = parts[len(parts)-1]
	if c.Debug {
		log.Printf("client - %s:%s: connected", c.LocalPort, c.Relay)
	}
	c.conn = conn
	// create the lock if empty as connection is established
	if c.lock == nil {
		c.lock = &sync.Mutex{}
	}
	_, err = c.readLine(smtp.STATUSRDY)
	if err != nil {
		c.Quit()
		return err
	}
	c.Connected = true
	return nil
}

func (c *SmtpClient) Close() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.Debug {
		log.Printf("client - disconnecting from %s", c.Relay)
	}
	if c.conn != nil {
		c.Connected = false
		c.Quit()
		return c.conn.Close()
	}
	return nil
}

func (c *SmtpClient) checkSmtpRespCode(expcode int, line string) error {
	if fmt.Sprintf("%d ", expcode) != line[:4] {
		return fmt.Errorf("unexpexted error code returned %d", expcode)
	}
	return nil
}

func (c *SmtpClient) sendCmd(command string) error {
	if c.Debug {
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
	line, err := tp.ReadLine()
	if err != nil {
		return "", err
	}
	if c.Debug {
		log.Printf("client - %s:%s: < %s", c.LocalPort, c.Relay, line)
	}
	err = c.checkSmtpRespCode(code, line)
	if err != nil {
		return "", err
	}
	return line, nil
}

func (c *SmtpClient) Quit() error {
	return c.sendCmd("QUIT")
}

func (c *SmtpClient) Helo() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	err := c.sendCmd(fmt.Sprintf("HELO %s", c.Hostname))
	if err != nil {
		return err
	}
	_, err = c.readLine(smtp.STATUSOK)
	if err != nil {
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
		c.Quit()
		return err
	}
	return nil
}

func (c *SmtpClient) Data(data string) error {
	err := c.sendCmd("DATA")
	if err != nil {
		return err
	}
	_, err = c.readLine(smtp.STATUSACT)
	if err != nil {
		c.Quit()
		return err
	}
	// sending data
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if c.Debug {
			log.Printf("client - %s:%s: > %s", c.LocalPort, c.Relay, line)
		}
		_, err := fmt.Fprintf(c.conn, "%s\r\n", line)
		if err != nil {
			return err
		}
	}
	if c.Debug {
		log.Printf("client - %s:%s: > .", c.LocalPort, c.Relay)
	}
	_, err = fmt.Fprint(c.conn, ".\r\n")
	if err != nil {
		return err
	}
	_, err = c.readLine(smtp.STATUSOK)
	if err != nil {
		c.Quit()
		return err
	}
	return nil
}

func (c *SmtpClient) SendMessage(msg message.Message) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	log.Printf("client - %s:%s:%s sending message", c.LocalPort, c.Relay, msg.Id)
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
		log.Printf("client - %s:%s:%s adding recipient %s", c.LocalPort, c.Relay, msg.Id, to)
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
		Debug:    debug,
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
