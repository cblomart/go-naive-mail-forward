package logger

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

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
var debugLock = sync.RWMutex{}
var TraceFacilities = map[string]bool{"all": false}
var traceLock = sync.RWMutex{}

func getFacility() string {
	_, file, _, ok := runtime.Caller(2)
	if !ok {
		return "unknown"
	}
	parts := strings.Split(file, "/")
	if len(parts) < 2 {
		return "main"
	}
	lastfolder := parts[len(parts)-2]
	if lastfolder == "go-naive-mail-forward" || lastfolder == "build" {
		return "main"
	}
	return lastfolder
}

func Debugf(format string, v ...interface{}) {
	facility := getFacility()
	debugLock.Lock()
	defer debugLock.Unlock()
	debug, ok := DebugFacilities[facility]
	if !ok {
		debug = DebugFacilities["all"]
		DebugFacilities[facility] = debug
	}

	if ok && debug {
		Logf(DEBUG, facility, fmt.Sprintf(format, v...))
	}
}

func Tracef(format string, v ...interface{}) {
	facility := getFacility()
	traceLock.Lock()
	defer traceLock.Unlock()
	trace, ok := TraceFacilities[facility]
	if !ok {
		trace = TraceFacilities["all"]
		TraceFacilities[facility] = trace
	}
	if ok && trace {
		Logf(TRACE, facility, fmt.Sprintf(format, v...))
	}
}

func Infof(format string, v ...interface{}) {
	Logf(INFO, getFacility(), fmt.Sprintf(format, v...))
}

func Errorf(format string, v ...interface{}) {
	Logf(ERROR, getFacility(), fmt.Sprintf(format, v...))
}

func Warnf(format string, v ...interface{}) {
	Logf(INFO, getFacility(), fmt.Sprintf(format, v...))
}

func Fatalf(format string, v ...interface{}) {
	Logf(INFO, getFacility(), fmt.Sprintf(format, v...))
	os.Exit(1)
}

func Logf(level string, facility string, format string, v ...interface{}) {
	log.Printf("%s - %-7s - %s", level, facility, fmt.Sprintf(format, v...))
}

func SetDebug(list string) {
	debugLock.Lock()
	defer debugLock.Unlock()
	Infof("setting debugging for: %s", list)
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
		Infof("switching %s", facility)
		if current, ok := DebugFacilities[facility]; ok {
			DebugFacilities[facility] = !current
		} else {
			DebugFacilities[facility] = true
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
		} else {
			TraceFacilities[facility] = true
		}
	}
}

func SetTrace(list string) {
	traceLock.Lock()
	defer traceLock.Unlock()
	Infof("setting tracing for: %s", list)
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
	debugLock.RLock()
	defer debugLock.RUnlock()
	facilities := []string{}
	for facility, status := range DebugFacilities {
		if facility == "all" {
			continue
		}
		if status {
			facilities = append(facilities, facility)
		}
	}
	return strings.Join(facilities, ",")
}

func GetTrace() string {
	traceLock.RLock()
	defer traceLock.RUnlock()
	facilities := []string{}
	for facility, status := range TraceFacilities {
		if facility == "all" {
			continue
		}
		if status {
			facilities = append(facilities, facility)
		}
	}
	return strings.Join(facilities, ",")
}
