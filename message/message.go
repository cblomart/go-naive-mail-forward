package message

import (
	"bufio"
	"cblomart/go-naive-mail-forward/address"
	"strings"
)

type Message struct {
	Id   string
	From *address.MailAddress
	To   []address.MailAddress
	Data string
}

func (m *Message) Domains() []string {
	// no to
	if len(m.To) == 0 {
		return []string{}
	}
	// only one recipient
	if len(m.To) == 1 {
		return []string{m.To[0].Domain}
	}
	// multiple recipient
	result := []string{}
	found := false
	for _, to := range m.To {
		found = false
		for _, domain := range result {
			if to.Domain == domain {
				found = true
				break
			}
		}
		if !found {
			result = append(result, to.Domain)
		}
	}
	return result
}

func (m *Message) ToDomains(domains []string) []string {
	result := []string{}
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimRight(domain, "."))
		for _, to := range m.To {
			if to.Domain == domain {
				result = append(result, to.String())
			}
		}
	}
	return result
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
