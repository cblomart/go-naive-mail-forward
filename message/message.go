package message

import (
	"bufio"
	"strings"
)

type Message struct {
	From     string
	To       string
	ToUser   string
	ToDomain string
	MX       string
	Data     string
}

func (m *Message) Signed() bool {
	scanner := bufio.NewScanner(strings.NewReader(m.Data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "DKIM-Signature:") {
			return true
		}
		if strings.HasPrefix(line, "MIME-Version:") {
			return false
		}
	}
	return false
}
