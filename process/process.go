package process

import (
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/rules"
	"cblomart/go-naive-mail-forward/smtp/client"
	"cblomart/go-naive-mail-forward/utils"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	log "cblomart/go-naive-mail-forward/logger"

	"github.com/google/uuid"
)

const (
	keepaliveInterval = 4
	connectionTimeout = 30
)

type Process struct {
	smtpPool []client.SmtpClient
	poolLock sync.RWMutex
	rules    *rules.Rules
	Hostname string
}

func NewProcessor(hostname string, processRules *rules.Rules) (*Process, error) {
	process := &Process{
		smtpPool: []client.SmtpClient{},
		poolLock: sync.RWMutex{},
		rules:    processRules,
		Hostname: hostname,
	}
	// start pool management
	go process.ManagePools()
	return process, nil
}

func (p *Process) ManagePools() {
	log.Infof("manage smtp connection pool (keepalive: %dm, nosendtimeout: %dm)", keepaliveInterval, connectionTimeout)
	// check every keepalive
	ticker := time.NewTicker(keepaliveInterval * time.Minute)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				go p.checkPools()
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
}

func (p *Process) checkPools() {
	// clean current pool
	c1 := p.cleanPool(true)
	// keepalive current pool
	p.keepAlivePool()
	// clean lingering connections that may have tripped
	c2 := p.cleanPool(true)
	// now we should be good
	if c1 || c2 {
		p.reportPool(true)
	}
}

func (p *Process) cleanPool(lock bool) bool {
	if lock {
		p.poolLock.Lock()
		defer p.poolLock.Unlock()
	}
	// suppose lock was already aquired
	minLastSent := time.Now().Add(-connectionTimeout * time.Minute)
	// clean disconnected or pools that did not send mails recently
	toRemove := []int{}
	for i := range p.smtpPool {
		if !p.smtpPool[i].Connected {
			log.Debugf("removing disconnected mx %s", p.smtpPool[i].Relay)
			toRemove = append(toRemove, i)
			continue
		}
		if p.smtpPool[i].LastSent.Before(minLastSent) {
			log.Debugf("removing timedout mx %s (%s)", p.smtpPool[i].Relay, time.Since(p.smtpPool[i].LastSent).String())
			toRemove = append(toRemove, i)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(toRemove)))
	for _, i := range toRemove {
		if p.smtpPool[i].Connected {
			// #nosec G104 ignore close issues
			p.smtpPool[i].Close()
		}
		// set element to remove to the last one
		p.smtpPool[i] = p.smtpPool[len(p.smtpPool)-1]
		// remove the last element of the slice
		p.smtpPool = p.smtpPool[:len(p.smtpPool)-1]
	}
	return len(toRemove) > 0
}

func (p *Process) keepAlivePool() {
	p.poolLock.RLock()
	defer p.poolLock.RUnlock()
	for _, client := range p.smtpPool {
		if client.Connected {
			// #nosec G104 ignore noop issues
			client.Noop()
		}
	}
}

func (p *Process) reportPool(lock bool) {
	if lock {
		p.poolLock.RLock()
		defer p.poolLock.RUnlock()
	}
	if len(p.smtpPool) == 0 {
		log.Debugf("no smtp connection")
		return
	}
	for _, client := range p.smtpPool {
		if !lock {
			log.Infof("smtp connection (server/domains/lastsent): %s/%s/%s", client.Relay, strings.Join(client.Domains, ","), time.Since(client.LastSent).String())
			continue
		}
		log.Debugf("smtp connection (server/domains/lastsent): %s/%s/%s", client.Relay, strings.Join(client.Domains, ","), time.Since(client.LastSent).String())
	}
}

//TODO: check for unmatched domains
func (p *Process) Handle(msg message.Message) (string, bool, error) {
	// id the message
	if len(msg.Id) == 0 {
		msg.Id = uuid.NewString()
	}

	// update recipients following rules
	p.rules.UpdateMessage(&msg)

	// if destination doesn't go anywhere return an error
	if len(msg.To) == 0 {
		log.Infof("%s: message has no destination", msg.Id)
		return "", true, fmt.Errorf("no recipients")
	}

	// check that message is signed
	if !msg.Signed() {
		log.Warnf("%s: message is not signed", msg.Id)
	}

	// find the relays to send to
	targetSMTP := p.findOrConnectSMTP(msg.Domains())

	// create a waitgroup for client sends
	var wg sync.WaitGroup
	wg.Add(len(targetSMTP))
	// channel to recieve results
	okChan := make(chan bool, len(targetSMTP))
	// start gofunc to send messages
	for _, i := range targetSMTP {
		go SendAsync(p.smtpPool[i], msg, &wg, okChan)
	}

	// wait for messages to be sent
	wg.Wait()
	close(okChan)

	// evaluate result
	result := false
	for res := range okChan {
		if res {
			result = true
			break
		}
	}

	// status on connections
	p.reportPool(false)

	// return result
	if !result {
		return msg.Id, false, fmt.Errorf("could not send message to at least one relay")
	}
	return msg.Id, false, nil
}

func (p *Process) mapDomainToSMTP(domains []string) ([]int, []int) {
	// list the pools to run the message to
	targetSMTP := []int{}
	// match domains against existing smtp connections
	matchedDomains := []int{}
	for i := range p.smtpPool {
		for _, msgDomain := range domains {
			j := utils.ContainsString(p.smtpPool[i].Domains, msgDomain)
			if j >= 0 {
				// add to smtp list if not yet in it
				if utils.ContainsInt(targetSMTP, i) <= 0 {
					targetSMTP = append(targetSMTP, i)
				}
				// add matched domain
				matchedDomains = append(matchedDomains, j)
			}
		}
	}
	return targetSMTP, matchedDomains
}

func (p *Process) findSMTP(domain string, mxs []*net.MX) int {
	// match mail exchanger against pool
	for _, mx := range mxs {
		for i := range p.smtpPool {
			if strings.EqualFold(strings.TrimRight(mx.Host, "."), strings.TrimRight(p.smtpPool[i].Relay, ".")) {
				// update pool data with domain
				p.smtpPool[i].Domains = append(p.smtpPool[i].Domains, domain)
				return i
			}
		}
	}
	return -1
}

func (p *Process) addSMTP(domain string, mxs []*net.MX) int {
	for _, mx := range mxs {
		// create smtp client
		client := &client.SmtpClient{
			Relay:    mx.Host,
			Domains:  []string{domain},
			Hostname: p.Hostname,
			LastSent: time.Now(),
		}
		err := client.StartSession()
		if err != nil {
			log.Errorf("could not start session with mx %s for %s", mx.Host, domain)
			continue
		}
		// add client to the pool
		p.smtpPool = append(p.smtpPool, *client)
		//targetSMTP = append(targetSMTP, len(p.smtpPool)-1)
		log.Infof("connected to mx %s for %s", mx.Host, domain)
		return len(p.smtpPool) - 1
	}
	return -1
}

func (p *Process) findOrConnectSMTP(domains []string) []int {
	// connecting to relays to send to (or reusing existing ones)
	log.Debugf("mapping smtp relays to send to for %s", strings.Join(domains, ", "))
	// lock the pool
	p.poolLock.Lock()
	defer p.poolLock.Unlock()
	// status on connections
	p.reportPool(false)
	// list the pools to run the message to
	targetSMTP, matchedDomains := p.mapDomainToSMTP(domains)
	sort.Sort(sort.Reverse(sort.IntSlice(matchedDomains)))
	// remove matched domains from list
	for _, i := range matchedDomains {
		domains[i] = domains[len(domains)-1]
		domains = domains[:len(domains)-1]
	}
	// lookup the remaining domains
	for _, domain := range domains {
		// mail exchangers for domain
		mxs, err := net.LookupMX(domain)
		if err != nil {
			log.Infof("could not find mx for %s", domain)
			continue
		}
		//check if we have a smtppool for this domain
		i := p.findSMTP(domain, mxs)
		if i >= 0 {
			targetSMTP = append(targetSMTP, i)
			continue
		}
		// domain not found let's add a smtp connection
		i = p.addSMTP(domain, mxs)
		if i >= 0 {
			targetSMTP = append(targetSMTP, i)
			break
		}
		log.Infof("could find or connect to any mx for %s", domain)
	}
	return targetSMTP
}

func SendAsync(client client.SmtpClient, msg message.Message, wg *sync.WaitGroup, okChan chan bool) {
	defer wg.Done()
	err := client.SendMessage(msg)
	if err != nil {
		log.Infof("%s: could not send via %s: %s", msg.Id, client.Relay, err.Error())
		okChan <- false
		return
	}
	log.Infof("%s: sent via %s", msg.Id, client.Relay)
	okChan <- true
}
