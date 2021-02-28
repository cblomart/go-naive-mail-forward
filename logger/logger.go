package logger

import (
	"fmt"
	"os"

	"log"
)

const (
	DEBUG = "debug"
	INFO  = "info "
	WARN  = "warn "
	ERROR = "error"
	FATAL = "fatal"
)

var DebugFacilities = map[string]bool{}

func Debugf(facility string, format string, v ...interface{}) {
	//_, file, _, ok := runtime.Caller(1)
	debug, ok := DebugFacilities[facility]
	if !ok {
		debug = false
		DebugFacilities[facility] = debug
	}
	if ok && debug {
		Logf(DEBUG, facility, fmt.Sprintf(format, v...))
	}
}

func Infof(facility string, format string, v ...interface{}) {
	Logf(INFO, facility, fmt.Sprintf(format, v...))
}

func Warnf(facility string, format string, v ...interface{}) {
	Logf(INFO, facility, fmt.Sprintf(format, v...))
}

func Fatalf(facility string, format string, v ...interface{}) {
	Logf(INFO, facility, fmt.Sprintf(format, v...))
	os.Exit(1)
}

func Logf(level string, facility string, format string, v ...interface{}) {
	log.Printf("%s - %s - %s", level, facility, fmt.Sprintf(format, v...))
}
