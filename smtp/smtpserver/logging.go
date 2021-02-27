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
				Debug = !Debug
			case "process":
				process.Debug = !process.Debug
			case "rule":
				rules.Debug = !rules.Debug
			case "client":
				smtpclient.Debug = !rules.Debug
			default:
				log.Printf("unknown component: %s", comp)
			}
		}
	} else {
		Debug = false
		process.Debug = false
		rules.Debug = false
		smtpclient.Debug = false
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
				Trace = !Trace
			case "client":
				smtpclient.Trace = !smtpclient.Trace
			default:
				log.Printf("unknown component: %s", comp)
			}
		}
	} else {
		Trace = false
		smtpclient.Trace = false
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
