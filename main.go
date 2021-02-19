package main

import (
	"cblomart/go-naive-mail-forward/smtp"
	"cblomart/go-naive-mail-forward/store"
	"flag"
	"fmt"
	"log"
	"net"
)

const (
	hostname = "smtp.zerottl.cc"
	OK       = 220
)

var (
	debug      bool
	servername string
	storage    string
	port       int
)

func init() {
	flag.BoolVar(&debug, "debug", false, "show debug messages")
	flag.BoolVar(&debug, "d", false, "show debug messages")
	flag.StringVar(&servername, "servername", "localhost", "hostname we are serving")
	flag.StringVar(&servername, "n", "localhost", "hostname we are serving")
	flag.StringVar(&storage, "storage", "localhost", "storage connection")
	flag.StringVar(&storage, "s", "localhost", "storage connection")
	flag.IntVar(&port, "port", 25, "port to listen to")
	flag.IntVar(&port, "p", 25, "port to listen to")
}

func main() {
	log.Print("Starting Golang Naive Mail Forwarder")
	flag.Parse()
	// listen to port 25 (smtp)
	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalln(err.Error())
	}
	defer listen.Close()

	// create the store
	s, err := store.NewStore(storage)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Printf("Instantiated %s storage\n", s.Type())

	//handle connections
	log.Printf("Listining on %s:%d and waiting for connections\n", servername, port)
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatalln(err.Error())
		}
		go smtp.HandleSmtpConn(conn, servername, s, debug)
	}
}
