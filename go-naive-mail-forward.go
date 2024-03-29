package main

//go:generate git-version

import (
	"cblomart/go-naive-mail-forward/cert"
	"cblomart/go-naive-mail-forward/healthcheck"
	log "cblomart/go-naive-mail-forward/logger"
	"cblomart/go-naive-mail-forward/process"
	"cblomart/go-naive-mail-forward/rules"
	"cblomart/go-naive-mail-forward/smtp/server"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/microsoft/ApplicationInsights-Go/appinsights"
)

const (
	envPrefix = "FORWARDER_"
	OK        = 220 // OK message
)

var (
	debug              string
	trace              string
	servername         string
	storage            string
	port               int
	forwards           string
	interval           string
	keyfile            string
	certfile           string
	gencert            bool
	dnsbl              string
	check              bool
	instrumentationKey string
	insecuretls        bool
	nospf              bool
	noblacklist        bool
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
	flag.StringVar(&instrumentationKey, "instkey", "", "Azure application insight instrumentation key")
	flag.BoolVar(&insecuretls, "insecuretls", false, "Allow insecure tls connections (client & server)")
	flag.BoolVar(&nospf, "nospf", false, "disable spf checking")
	flag.BoolVar(&noblacklist, "noblacklist", false, "disable ip blacklisting")
}

func main() {
	log.Infof("Starting Golang Naive Mail Forwarder (%s - %s - %s)", gitTag, gitBranch, gitShortCommit)
	flag.Parse()
	// check for environment variables
	flag.VisitAll(checkenv)

	// healthcheck
	if check {
		os.Exit(healthcheck.Check())
	}

	// set debugging
	log.SetDebug(debug)

	// set tracing
	log.SetTrace(trace)

	// initalise application insight if provided
	if len(instrumentationKey) > 0 {
		appinsights.NewTelemetryClient(instrumentationKey)
	}

	// get the rules
	forwardRules, err := rules.NewRules(forwards)
	if err != nil {
		log.Fatalf(err.Error())
	}
	domains := forwardRules.GetValidDomains()
	log.Infof("accepting domains: %s", strings.Join(domains, ", "))

	// generate certs
	if gencert {
		err := cert.GenCert(servername, keyfile, certfile)
		if err != nil {
			log.Fatalf(err.Error())
		}
	}

	// listen to port 25 (smtp)
	listen, err := net.ListenTCP("tcp", &net.TCPAddr{Port: port})
	if err != nil {
		log.Fatalf(err.Error())
	}
	defer listen.Close()

	// create the processor
	msgProcessor, err := process.NewProcessor(servername, forwardRules, insecuretls)
	if err != nil {
		log.Fatalf(err.Error())
	}

	//handle connections
	log.Infof("listening on %s:%d and waiting for connections\n", servername, port)
	for {
		conn, err := listen.AcceptTCP()
		if err != nil {
			log.Fatalf(err.Error())
		}
		go server.HandleSMTPConn(conn, servername, msgProcessor, domains, dnsbl, keyfile, certfile, insecuretls, nospf, noblacklist)
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
			log.Infof("environement variable %s set to empty value", prefix)
		}
		return
	}
	err := fl.Value.Set(value)
	if err != nil {
		log.Infof("could not update %s to %s from env: %s", fl.Name, value, err.Error())
		return
	}
	log.Infof("updated %s to %s from env", fl.Name, value)
}
