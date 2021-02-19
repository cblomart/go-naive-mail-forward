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
)

type SmtpClient struct {
	conn      net.Conn
	localPort string
	Relay     string
	Hostname  string
	Debug     bool
}

func (c *SmtpClient) Connect() error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:25", c.Relay))
	if err != nil {
		return err
	}
	// get local port
	parts := strings.Split(conn.LocalAddr().String(), ":")
	c.localPort = parts[len(parts)-1]
	if c.Debug {
		log.Printf("client - %s:%s: connected", c.localPort, c.Relay)
	}
	c.conn = conn
	_, err = c.readLine(smtp.STATUSRDY)
	if err != nil {
		c.Quit()
		return err
	}
	return nil
}

func (c *SmtpClient) Close() error {
	if c.Debug {
		log.Printf("client - disconnecting from %s", c.Relay)
	}
	if c.conn != nil {
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
		log.Printf("client - %s:%s: > %s", c.localPort, c.Relay, command)
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
		log.Printf("client - %s:%s: < %s", c.localPort, c.Relay, line)
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

func Send(hostname string, relay string, msgs []message.Message, debug bool) ([]string, error) {
	// create smtp client
	client := &SmtpClient{
		Relay:    relay,
		Debug:    debug,
		Hostname: hostname,
	}
	// connect to server
	err := client.Connect()
	if err != nil {
		return nil, err
	}
	// hello server
	err = client.Helo()
	if err != nil {
		return nil, err
	}
	// close connection on exit
	defer client.Close()
	return nil, nil
}
