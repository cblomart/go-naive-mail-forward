package address

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

type MailAddress struct {
	User   string
	Domain string
}

var (
	UserMatch   = regexp.MustCompile(`^[a-zA-Z0-9'_][a-zA-Z0-9'_.-]+[a-zA-Z0-9'_]$`)
	DomainMatch = regexp.MustCompile(`^([a-z0-9-]{1,63}\.)+[a-z]{2,63}\.?$`)
)

func NewMailAddress(address string) (*MailAddress, error) {
	parts := strings.Split(strings.ToLower(strings.TrimRight(strings.Trim(address, "<>"), ".")), "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("too much or too little in address")
	}
	ma := &MailAddress{
		User:   parts[0],
		Domain: parts[1],
	}
	if !ma.isValid() {
		return nil, fmt.Errorf("invalid address")
	}
	return ma, nil
}

func (ma *MailAddress) isValid() bool {
	// user and domain must be present
	if len(ma.User) == 0 || len(ma.Domain) == 0 {
		return false
	}
	// user and domain must be in a proper format
	if !UserMatch.MatchString(ma.User) || !DomainMatch.MatchString(ma.Domain) {
		return false
	}
	// mail exchangers must be known
	mxs, err := net.LookupMX(ma.Domain)
	if err != nil {
		return false
	}
	if len(mxs) == 0 {
		return false
	}
	return true
}

func (ma *MailAddress) String() string {
	return fmt.Sprintf("%s@%s", ma.User, ma.Domain)
}
