package healthcheck

import (
	log "cblomart/go-naive-mail-forward/logger"
	"fmt"
	"net/textproto"
)

const (
	Localhost   = "localhost"
	Healthcheck = "healthcheck"
)

func Check() int {
	conn, err := textproto.Dial("tcp", fmt.Sprintf("%s:25", Localhost))
	if err != nil {
		log.Errorf("error dialing %s: %s", fmt.Sprintf("%s:25", Localhost), err.Error())
		return 1
	}
	defer conn.Close()
	code, _, err := conn.ReadCodeLine(2)
	if err != nil {
		log.Errorf("unexpected welcome response (%d): %s", code, err.Error())
		return 1
	}
	err = conn.Writer.PrintfLine("NOOP %s", Healthcheck)
	if err != nil {
		log.Errorf("error sending noop: %s", err.Error())
		return 1
	}
	code, message, err := conn.ReadCodeLine(2)
	if err != nil {
		log.Errorf("unexpected noop response (%d): %s", code, err.Error())
		return 1
	}
	log.Infof("response: %s (%d)", message, code)
	return 0
}
