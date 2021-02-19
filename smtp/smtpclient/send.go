package smtpclient

import (
	"bufio"
	"cblomart/go-naive-mail-forward/message"
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
	// check welcome message from server
	// get a buffer reader
	reader := bufio.NewReader(c.conn)
	// get a text proto reader
	tp := textproto.NewReader(reader)
	line, err := tp.ReadLine()
	if err != nil {
		return err
	}
	if c.Debug {
		log.Printf("client - %s:%s: < %s", c.localPort, c.Relay, line)
	}
	return nil
}

func (c *SmtpClient) Close() error {
	if c.Debug {
		log.Printf("client - disconnecting from %s", c.Relay)
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func Send(relay string, msgs []message.Message, debug bool) ([]string, error) {
	// create smtp client
	client := &SmtpClient{
		Relay: relay,
		Debug: debug,
	}
	// connect to server
	err := client.Connect()
	if err != nil {
		return nil, err
	}
	// close connection on exit
	defer client.Close()
	return nil, nil
}
