package main

import (
	"cblomart/go-naive-mail-forward/smtp"
	"cblomart/go-naive-mail-forward/store"
	"log"
	"net"
)

const (
	hostname = "smtp.zerottl.cc"
	OK       = 220
)

func main() {
	log.Print("Starting Golang Naive Mail Forwarder")
	// listen to port 25 (smtp)
	listen, err := net.Listen("tcp", ":25")
	if err != nil {
		log.Fatalln(err.Error())
	}
	defer listen.Close()

	// create the store
	s, err := store.NewStore("memory")
	if err != nil {
		log.Fatalln(err.Error())
	}

	//handle connections
	log.Print("Listining to port 25 and waiting for connections")
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatalln(err.Error())
		}
		go smtp.HandleSmtpConn(conn, "zerottl.cc", s, true)
	}
}
