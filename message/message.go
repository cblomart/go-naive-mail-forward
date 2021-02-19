package message

import (
	"bufio"
	"cblomart/go-naive-mail-forward/address"
	"strings"
)

type Message struct {
	From *address.MailAddress
	To   []address.MailAddress
	Data string
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
