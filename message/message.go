package message

import (
	"bufio"
	"bytes"
	"cblomart/go-naive-mail-forward/address"
	"strings"
)

type Message struct {
	Id   string
	From *address.MailAddress
	To   []address.MailAddress
	Data []byte
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
	scanner := bufio.NewScanner(bytes.NewReader(m.Data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "DKIM-Signature:") {
			return true
		}
		if len(line) == 0 {
			return false
		}
	}
	return false
}

func (m *Message) Recipients() string {
	// get destination addresses
	addresses := make([]string, len(m.To))
	for i, ma := range m.To {
		addresses[i] = ma.String()
	}
	return strings.Join(addresses, ",")
}
