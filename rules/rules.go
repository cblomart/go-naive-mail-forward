package rules

import (
	"cblomart/go-naive-mail-forward/address"
	"fmt"
	"log"
	"regexp"
	"strings"
)

type Rules []Rule

func NewRules(rules string) (*Rules, error) {
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

type Rule struct {
	FromUser *regexp.Regexp
	To       []address.MailAddress
	Domain   string
}

func (r *Rule) Evaluate(ma address.MailAddress) []address.MailAddress {
	if strings.ToUpper(strings.TrimRight(ma.Domain, ".")) != strings.ToUpper(strings.TrimRight(r.Domain, ".")) {
		return nil
	}
	if !r.FromUser.MatchString(ma.User) {
		return nil
	}
	return r.To
}

func NewRule(rule string) (*Rule, error) {
	parts := strings.Split(rule, ":")
	if len(parts) < 2 {
		return nil, fmt.Errorf("rule needs at least two parts")
	}
	r := &Rule{}
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
	r.FromUser = regexp.MustCompile(strings.Replace(fromParts[0], "*", "[0-9A-Za-z_])", -1))
	r.To = []address.MailAddress{}
	for _, addr := range parts[1:] {
		ma, err := address.NewMailAddress(addr)
		if err != nil {
			log.Printf("rules - invalid address: %s", addr)
			continue
		}
		r.To = append(r.To, *ma)
	}
	return r, nil
}
