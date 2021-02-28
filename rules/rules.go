package rules

import (
	"cblomart/go-naive-mail-forward/address"
	"cblomart/go-naive-mail-forward/message"
	"fmt"
	"regexp"
	"strings"

	log "cblomart/go-naive-mail-forward/logger"

	"github.com/google/uuid"
)

type Rules []Rule

var (
	Debug = false
)

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
			log.Infof("rules", "invalid rule %s: %s", strRule, err.Error())
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
	log.Infof("rules", "%s: forwarding: %s > %s", msg.Id, original, updated)
}

type Rule struct {
	Invert   bool
	FromUser *regexp.Regexp
	To       []address.MailAddress
	Domain   string
}

func (r *Rule) Evaluate(ma address.MailAddress) []address.MailAddress {
	toAddr := make([]address.MailAddress, len(r.To))
	copy(toAddr, r.To)
	log.Debugf("rules", "riginal addresses %v", toAddr)
	if !strings.EqualFold(strings.TrimRight(ma.Domain, "."), strings.TrimRight(r.Domain, ".")) {
		return nil
	}
	// check match with inverstion
	if !r.Match(ma) {
		log.Debugf("rules", "%s didn't match %s", ma.User, r.FromUser.String())
		return nil
	}
	for i := range toAddr {
		if len(toAddr[i].User) == 0 {
			toAddr[i].User = ma.User
		}
	}
	log.Debugf("rules", "forwarding addresses %v", toAddr)
	return toAddr
}

func (r *Rule) Match(addr address.MailAddress) bool {
	match := r.FromUser.MatchString(addr.User)
	if match {
		log.Debugf("rules", "%s matched against '%s'", addr.User, r.FromUser.String())
	}
	if r.Invert {
		match = !match
	}
	return match
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
		return nil, fmt.Errorf("invalid domain %s", fromParts[1])
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
		checked := CheckAddr(addr)
		if checked == nil {
			continue
		}
		r.To = append(r.To, *checked)
	}
	return r, nil
}

func CheckAddr(addr string) *address.MailAddress {
	log.Debugf("rules", "checking target %s", addr)
	addrParts := strings.Split(addr, "@")
	if len(addrParts) != 2 {
		log.Infof("rules", "invalid target address: %s", addr)
		return nil
	}
	user := addrParts[0]
	domain := addrParts[1]
	if !address.DomainMatch.MatchString(domain) {
		log.Infof("rules", "invalid target domain: %s", addr)
		return nil
	}
	return &address.MailAddress{Domain: domain, User: user}
}
