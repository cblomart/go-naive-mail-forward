package rules

import (
	"cblomart/go-naive-mail-forward/address"
	"cblomart/go-naive-mail-forward/message"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

type Rules []Rule

var Debug = true

func NewRules(rules string) (*Rules, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules")
	}
	parts := strings.Split(rules, ";")
	if len(parts) == 0 {
		return nil, fmt.Errorf("no rules")
	}
	rs := Rules{}
	for _, strRule := range parts {
		rule, err := NewRule(strRule)
		if err != nil {
			log.Printf("rules - invalid rule %s", strRule)
			continue
		}
		rs = append(rs, *rule)
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("no rules parsed")
	}
	return &rs, nil
}

func (rs *Rules) GetValidDomains() []string {
	domains := make([]string, len(*rs))
	for i, rule := range *rs {
		domains[i] = rule.Domain
	}
	return domains
}

func (rs *Rules) Evaluate(mas []address.MailAddress) []address.MailAddress {
	check := make(map[string]address.MailAddress)
	for _, rule := range *rs {
		for _, ma := range mas {
			ruleAddresses := rule.Evaluate(ma)
			for _, ruleAddress := range ruleAddresses {
				if _, ok := check[ruleAddress.String()]; !ok {
					check[ruleAddress.String()] = ruleAddress
				}
			}
		}
	}
	result := make([]address.MailAddress, len(check))
	i := 0
	for _, address := range check {
		result[i] = address
		i++
	}
	return result
}

func (rs *Rules) UpdateMessage(msg *message.Message) {
	if len(msg.Id) == 0 {
		msg.Id = uuid.NewString()
	}
	// updating to from rules
	rcptTo := make([]string, len(msg.To))
	for i, to := range msg.To {
		rcptTo[i] = to.String()
	}
	original := strings.Join(rcptTo, ";")
	msg.To = rs.Evaluate(msg.To)
	rcptTo = make([]string, len(msg.To))
	for i, to := range msg.To {
		rcptTo[i] = to.String()
	}
	updated := strings.Join(rcptTo, ";")
	log.Printf("rules - %s: forwarding: %s > %s", msg.Id, original, updated)
}

type Rule struct {
	Invert   bool
	FromUser *regexp.Regexp
	To       []address.MailAddress
	Domain   string
}

func (r *Rule) Evaluate(ma address.MailAddress) []address.MailAddress {
	toAddr := []address.MailAddress{}
	copy(toAddr, r.To)
	if Debug {
		log.Printf("rules - original addresses %v", toAddr)
	}
	if strings.ToUpper(strings.TrimRight(ma.Domain, ".")) != strings.ToUpper(strings.TrimRight(r.Domain, ".")) {
		return nil
	}
	// check match with inverstion
	if Debug {
		log.Printf("rules - matching %s against %s", ma.User, r.FromUser.String())
	}
	match := r.FromUser.MatchString(ma.User)
	if match && Debug {
		log.Printf("rules - %s matched against '%s'", ma.User, r.FromUser.String())
	}
	if r.Invert {
		match = !match
	}
	if !match {
		return nil
	}
	if Debug {
		log.Printf("rules - %s matched against %s (invert: %v)", ma.User, r.FromUser.String(), r.Invert)
	}
	for i := range toAddr {
		if len(toAddr[i].User) == 0 {
			toAddr[i].User = ma.User
		}
	}
	if Debug {
		log.Printf("rules - forwarding addresses %v", toAddr)
	}
	return toAddr
}

func NewRule(rule string) (*Rule, error) {
	parts := strings.Split(rule, ":")
	if len(parts) < 2 {
		return nil, fmt.Errorf("rule needs at least two parts")
	}
	r := &Rule{}
	if parts[0][0] == '!' {
		r.Invert = true
		parts[0] = parts[0][1:]
	}
	fromParts := strings.Split(parts[0], "@")
	if len(fromParts) != 2 {
		return nil, fmt.Errorf("too much or too little information in source")
	}
	if !address.DomainMatch.MatchString(fromParts[1]) {
		return nil, fmt.Errorf("invalid domain")
	}
	r.Domain = fromParts[1]
	if len(fromParts[0]) == 0 {
		fromParts[0] = "*"
	}
	regex := strings.Replace(fromParts[0], "*", "[0-9A-Za-z_]*", -1)
	if regex[0] != '^' {
		regex = fmt.Sprintf("^%s", regex)
	}
	if regex[len(regex)-1] != '$' {
		regex = fmt.Sprintf("%s$", regex)
	}
	r.FromUser = regexp.MustCompile(regex)
	r.To = []address.MailAddress{}
	for _, addr := range parts[1:] {
		if Debug {
			log.Printf("rules - checking target %s", addr)
		}
		addrParts := strings.Split(addr, "@")
		if len(addrParts) != 2 {
			log.Printf("rules - invalid target address: %s", addr)
			continue
		}
		user := addrParts[0]
		domain := addrParts[1]
		if !address.DomainMatch.MatchString(domain) {
			log.Printf("rules - invalid target domain: %s", addr)
			continue
		}
		r.To = append(r.To, address.MailAddress{Domain: domain, User: user})
	}
	return r, nil
}
