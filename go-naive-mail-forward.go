package main

//go:generate git-version

import (
	"cblomart/go-naive-mail-forward/cert"
	"cblomart/go-naive-mail-forward/process"
	"cblomart/go-naive-mail-forward/rules"
	"cblomart/go-naive-mail-forward/smtp/smtpserver"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

const (
	envPrefix = "FORWARDER_"
	OK        = 220
)

var (
	debug      string
	trace      string
	servername string
	storage    string
	port       int
	forwards   string
	interval   string
	keyfile    string
	certfile   string
	gencert    bool
	dnsbl      string
	check      bool
)

func init() {
	flag.StringVar(&servername, "servername", "localhost", "hostname we are serving")
	flag.StringVar(&servername, "n", "localhost", "hostname we are serving")
	flag.IntVar(&port, "port", 25, "port to listen to")
	flag.IntVar(&port, "p", 25, "port to listen to")
	flag.StringVar(&storage, "storage", "memory", "storage connection")
	flag.StringVar(&storage, "s", "memory", "storage connection")
	flag.StringVar(&debug, "debug", "", "show debug messages (comma separarted, server>process>rule>client or all)")
	flag.StringVar(&debug, "d", "", "show debug messages (comma separarted, server>process>rule>client or all)")
	flag.StringVar(&trace, "trace", "", "show traces (comma separarted, server,client or all)")
	flag.StringVar(&trace, "t", "", "show traces  (comma separarted, server,client or all)")
	flag.StringVar(&forwards, "rules", "", "rules to apply")
	flag.StringVar(&forwards, "r", "", "rules to apply")
	flag.StringVar(&dnsbl, "dnsbl", "zen.spamhaus.org", "dns blackhole list (comma separated)")
	flag.StringVar(&interval, "interval", "60s", "interval between sends")
	flag.StringVar(&interval, "i", "60s", "interval between sends")
	flag.StringVar(&keyfile, "key", "./smtp.key", "certificate key file (no password)")
	flag.StringVar(&certfile, "cert", "./smtp.crt", "certificate file")
	flag.BoolVar(&gencert, "gencert", true, "generate certificate")
	flag.BoolVar(&check, "check", false, "checks the server status")
}

func main() {
	log.Printf("Starting Golang Naive Mail Forwarder (%s - %s - %s)", gitTag, gitBranch, gitShortCommit)
	flag.Parse()
	// check for environment variables
	flag.VisitAll(checkenv)

	// healthcheck
	if check {
		os.Exit(smtpserver.Check())
	}

	// set debugging
	smtpserver.SetDebug(debug)

	// set tracing
	smtpserver.SetTrace(trace)

	// get the rules
	forwardRules, err := rules.NewRules(forwards)
	if err != nil {
		log.Fatalln(err.Error())
	}
	domains := forwardRules.GetValidDomains()
	log.Printf("accepting domains: %s", strings.Join(domains, ", "))

	// generate certs
	if gencert {
		err := cert.GenCert(servername, keyfile, certfile)
		if err != nil {
			log.Fatalln(err.Error())
		}
	}
	// listen to port 25 (smtp)
	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalln(err.Error())
	}
	defer listen.Close()

	// create the processor
	msgProcessor, err := process.NewProcessor(servername, forwardRules)
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
		go smtpserver.HandleSmtpConn(conn, servername, msgProcessor, domains, dnsbl, keyfile, certfile)
	}
}

func checkenv(fl *flag.Flag) {
	// check only long args
	if len(fl.Name) <= 1 {
		return
	}
	value := ""
	prefix := strings.ToUpper(fmt.Sprintf("%s%s=", envPrefix, fl.Name))
	found := false
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, prefix) {
			continue
		}
		found = true
		value = strings.TrimSpace(env[len(prefix):])
		break
	}
	if len(value) == 0 {
		if found {
			log.Printf("environement variable %s set to empty value", prefix)
		}
		return
	}
	err := fl.Value.Set(value)
	if err != nil {
		log.Printf("could not update %s to %s from env: %s", fl.Name, value, err.Error())
		return
	}
	log.Printf("updated %s to %s from env", fl.Name, value)
}
