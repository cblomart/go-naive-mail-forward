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
	UserMatch   = regexp.MustCompile(`^[a-zA-Z0-9'_]([a-zA-Z0-9'_.-]*[a-zA-Z0-9'_])?$`)
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
	err := ma.isValid()
	if err != nil {
		return nil, err
	}
	return ma, nil
}

func (ma *MailAddress) isValid() error {
	// user and domain must be present
	if len(ma.User) == 0 {
		return fmt.Errorf("address has no user")
	}
	if len(ma.Domain) == 0 {
		return fmt.Errorf("address has no domain")
	}
	// user and domain must be in a proper format
	if !UserMatch.MatchString(ma.User) {
		return fmt.Errorf("address user in incorect format")
	}
	if !DomainMatch.MatchString(ma.Domain) {
		return fmt.Errorf("address domain in incorect format")
	}
	// mail exchangers must be known
	mxs, err := net.LookupMX(ma.Domain)
	if err != nil {
		return fmt.Errorf("cannot get mx for %s", ma.Domain)
	}
	if len(mxs) == 0 {
		return fmt.Errorf("no mx known for %s", ma.Domain)
	}
	return nil
}

func (ma *MailAddress) String() string {
	return fmt.Sprintf("%s@%s", ma.User, ma.Domain)
}
