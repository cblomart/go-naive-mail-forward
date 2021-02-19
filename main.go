package main

import (
	"cblomart/go-naive-mail-forward/rules"
	"cblomart/go-naive-mail-forward/smtp"
	"cblomart/go-naive-mail-forward/store"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
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
	flag.StringVar(&interval, "interval", "30s", "interval between sends")
	flag.StringVar(&interval, "i", "30s", "interval between sends")
}

func main() {
	log.Print("Starting Golang Naive Mail Forwarder")
	flag.Parse()

	// get the rules
	f, err := rules.NewRules(forwards)
	if err != nil {
		log.Fatalln(err.Error())
	}
	domains := f.GetValidDomains()
	log.Printf("accepting domains: %s", strings.Join(domains, ", "))

	// listen to port 25 (smtp)
	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalln(err.Error())
	}
	defer listen.Close()

	// create the store
	s, err := store.NewStore(storage, f)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Printf("Instantiated %s storage\n", s.Type())

	// start scheduled storage send process
	d, err := time.ParseDuration(interval)
	if err != nil {
		log.Fatalln(err.Error())
	}
	ticker := time.NewTicker(d)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				go smtp.Send(s)
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	//handle connections
	log.Printf("Listining on %s:%d and waiting for connections\n", servername, port)
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Fatalln(err.Error())
		}
		go smtp.HandleSmtpConn(conn, servername, s, domains, debug)
	}
}
