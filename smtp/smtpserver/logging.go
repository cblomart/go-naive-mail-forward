package smtpserver

import (
	"cblomart/go-naive-mail-forward/process"
	"cblomart/go-naive-mail-forward/rules"
	"cblomart/go-naive-mail-forward/smtp/smtpclient"
	"log"
	"regexp"
	"strings"
)

var DebugParamMatch = regexp.MustCompile(`(?i)^((all|on|none|off|process|rule|client),?)+$`)

func SetDebug(list string) {
	if !DebugParamMatch.MatchString(list) {
		return
	}
	for _, comp := range strings.Split(list, ",") {
		log.Printf("switching debugging for %s", comp)
		switch comp {
		case "all", "on":
			Debug = true
			process.Debug = true
			rules.Debug = true
			smtpclient.Debug = true
		case "server":
			Debug = true
		case "process":
			process.Debug = true
		case "rule":
			rules.Debug = true
		case "client":
			smtpclient.Debug = true
		case "none", "off":
			Debug = false
			process.Debug = false
			rules.Debug = false
			smtpclient.Debug = false
		default:
			log.Printf("unknown component: %s", comp)
		}
	}

}

func SetTrace(list string) {
	if !DebugParamMatch.MatchString(list) {
		return
	}
	for _, comp := range strings.Split(list, ",") {
		log.Printf("enabling tracing for %s", comp)
		switch comp {
		case "all", "on":
			Trace = true
			smtpclient.Trace = true
		case "server":
			Trace = true
		case "client":
			smtpclient.Trace = true
		case "none", "off":
			Trace = false
			smtpclient.Trace = false
		default:
			log.Printf("unknown component: %s", comp)
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
