package smtpserver

import (
	"cblomart/go-naive-mail-forward/process"
	"cblomart/go-naive-mail-forward/rules"
	"cblomart/go-naive-mail-forward/smtp/smtpclient"
	"log"
	"strings"
)

func SetDebug(debug string) {
	// set debugging
	if len(debug) != 0 {
		if debug == "all" {
			debug = "server,process,rule,client"
		}
		for _, comp := range strings.Split(debug, ",") {
			log.Printf("enabling debugging for %s", comp)
			switch comp {
			case "server":
				Debug = true
			case "process":
				process.Debug = true
			case "rule":
				rules.Debug = true
			case "client":
				smtpclient.Debug = true
			default:
				log.Printf("unknown component: %s", comp)
			}
		}
	}
}

func SetTrace(trace string) {
	// set tracing
	if len(trace) != 0 {
		if trace == "all" {
			trace = "server,client"
		}
		for _, comp := range strings.Split(trace, ",") {
			log.Printf("enabling tracing for %s", comp)
			switch comp {
			case "server":
				Trace = true
			case "client":
				smtpclient.Trace = true
			default:
				log.Printf("unknown component: %s", comp)
			}
		}
	}
}

func GetDebug() string {
	facilities := []string{}
	if Debug {
		facilities = append(facilities, "server")
	}
	if process.Debug {
		facilities = append(facilities, "process")
	}
	if rules.Debug {
		facilities = append(facilities, "rule")
	}
	if smtpclient.Debug {
		facilities = append(facilities, "client")
	}
	return strings.Join(facilities, ",")
}

func GetTrace() string {
	facilities := []string{}
	if Trace {
		facilities = append(facilities, "server")
	}
	if smtpclient.Trace {
		facilities = append(facilities, "client")
	}
	return strings.Join(facilities, ",")
}
