package smtpclient

import (
	"cblomart/go-naive-mail-forward/message"
	"fmt"
	"log"
	"net"
)

type SmtpClient struct {
	conn  net.Conn
	Relay string
	Debug bool
}

func (c *SmtpClient) Connect() error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:25", c.Relay))
	if err != nil {
		return err
	}
	if c.Debug {
		log.Printf("client - connected to %s at %s", c.Relay, conn.RemoteAddr().String())
	}
	c.conn = conn
	return nil
}

func (c *SmtpClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	if c.Debug {
		log.Printf("client - disconnected from %s", c.Relay)
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
