package logger

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"log"
)

const (
	DEBUG = "debug"
	INFO  = "info "
	WARN  = "warn "
	ERROR = "error"
	FATAL = "fatal"
	TRACE = "trace"
)

var DebugFacilities = map[string]bool{"all": false}
var TraceFacilities = map[string]bool{"all": false}

func Debugf(facility string, format string, v ...interface{}) {
	_, file, _, ok := runtime.Caller(1)
	if ok {
		log.Print(file)
	}
	debug, ok := DebugFacilities[facility]
	if !ok {
		debug = DebugFacilities["all"]
		DebugFacilities[facility] = debug
	}
	if ok && debug {
		Logf(DEBUG, facility, fmt.Sprintf(format, v...))
	}
}

func Tracef(facility string, format string, v ...interface{}) {
	_, file, _, ok := runtime.Caller(1)
	if ok {
		log.Print(file)
	}
	//_, file, _, ok := runtime.Caller(1)
	trace, ok := TraceFacilities[facility]
	if !ok {
		trace = TraceFacilities["all"]
		TraceFacilities[facility] = trace
	}
	if ok && trace {
		Logf(TRACE, facility, fmt.Sprintf(format, v...))
	}
}

func Infof(facility string, format string, v ...interface{}) {
	_, file, _, ok := runtime.Caller(1)
	if ok {
		log.Print(file)
	}
	Logf(INFO, facility, fmt.Sprintf(format, v...))
}

func Errorf(facility string, format string, v ...interface{}) {
	_, file, _, ok := runtime.Caller(1)
	if ok {
		log.Print(file)
	}
	Logf(ERROR, facility, fmt.Sprintf(format, v...))
}

func Warnf(facility string, format string, v ...interface{}) {
	_, file, _, ok := runtime.Caller(1)
	if ok {
		log.Print(file)
	}
	Logf(INFO, facility, fmt.Sprintf(format, v...))
}

func Fatalf(facility string, format string, v ...interface{}) {
	_, file, _, ok := runtime.Caller(1)
	if ok {
		log.Print(file)
	}
	Logf(INFO, facility, fmt.Sprintf(format, v...))
	os.Exit(1)
}

func Logf(level string, facility string, format string, v ...interface{}) {
	log.Printf("%s - %s - %s", level, facility, fmt.Sprintf(format, v...))
}

func SetDebug(list string) {
	switch list {
	case "none", "off":
		DebugFacilities["all"] = false
		for facility := range DebugFacilities {
			DebugFacilities[facility] = false
		}
	case "all", "on":
		DebugFacilities["all"] = true
		for facility := range DebugFacilities {
			DebugFacilities[facility] = true
		}
	default:
		switchDebugFacilities(strings.Split(list, ","))
	}
}

func switchDebugFacilities(facilities []string) {
	for _, facility := range facilities {
		if facility == "none" || facility == "off" || facility == "all" || facility == "on" {
			continue
		}
		if current, ok := DebugFacilities[facility]; ok {
			DebugFacilities[facility] = !current
		}
	}
}

func switchTraceFacilities(facilities []string) {
	for _, facility := range facilities {
		if facility == "none" || facility == "off" || facility == "all" || facility == "on" {
			continue
		}
		if current, ok := TraceFacilities[facility]; ok {
			TraceFacilities[facility] = !current
		}
	}
}

func SetTrace(list string) {
	switch list {
	case "none", "off":
		TraceFacilities["all"] = false
		for facility := range TraceFacilities {
			TraceFacilities[facility] = false
		}
	case "all", "on":
		TraceFacilities["all"] = true
		for facility := range DebugFacilities {
			TraceFacilities[facility] = true
		}
	default:
		switchTraceFacilities(strings.Split(list, ","))
	}
}

func GetDebug() string {
	facilities := []string{}
	for facility := range DebugFacilities {
		if facility == "all" {
			continue
		}
		facilities = append(facilities, facility)
	}
	return strings.Join(facilities, ",")
}

func GetTrace() string {
	facilities := []string{}
	for facility := range TraceFacilities {
		if facility == "all" {
			continue
		}
		facilities = append(facilities, facility)
	}
	return strings.Join(facilities, ",")
}
