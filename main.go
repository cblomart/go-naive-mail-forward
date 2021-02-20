package main

import (
	"cblomart/go-naive-mail-forward/process"
	"cblomart/go-naive-mail-forward/rules"
	"cblomart/go-naive-mail-forward/smtp/smtpserver"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
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
	forwards   string
	interval   string
)

func init() {
	flag.StringVar(&servername, "servername", "localhost", "hostname we are serving")
	flag.StringVar(&servername, "n", "localhost", "hostname we are serving")
	flag.IntVar(&port, "port", 25, "port to listen to")
	flag.IntVar(&port, "p", 25, "port to listen to")
	flag.StringVar(&storage, "storage", "memory", "storage connection")
	flag.StringVar(&storage, "s", "memory", "storage connection")
	flag.BoolVar(&debug, "debug", false, "show debug messages")
	flag.BoolVar(&debug, "d", false, "show debug messages")
	flag.StringVar(&forwards, "rules", "", "rules to apply")
	flag.StringVar(&forwards, "r", "", "rules to apply")
	flag.StringVar(&interval, "interval", "60s", "interval between sends")
	flag.StringVar(&interval, "i", "60s", "interval between sends")
}

func main() {
	log.Print("Starting Golang Naive Mail Forwarder")
	flag.Parse()

	// get the rules
	forwardRules, err := rules.NewRules(forwards)
	if err != nil {
		log.Fatalln(err.Error())
	}
	domains := forwardRules.GetValidDomains()
	log.Printf("accepting domains: %s", strings.Join(domains, ", "))

	// listen to port 25 (smtp)
	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalln(err.Error())
	}
	defer listen.Close()

	// create the processor
	msgProcessor, err := process.NewProcessor(servername, forwardRules, debug)
	if err != nil {
		log.Fatalln(err.Error())
	}

	//handle connections
	log.Printf("listening on %s:%d and waiting for connections\n", servername, port)
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatalln(err.Error())
		}
		go smtpserver.HandleSmtpConn(conn, servername, msgProcessor, domains, debug)
	}
}
