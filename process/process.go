package process

import (
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/rules"
	"cblomart/go-naive-mail-forward/smtp/client"
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
	c1 := p.cleanPool()
	// keepalive current pool
	p.keepAlivePool()
	// clean lingering connections that may have tripped
	c2 := p.cleanPool()
	// now we should be good
	if c1 || c2 {
		p.reportPool()
	}
}

func (p *Process) cleanPool() bool {
	p.poolLock.Lock()
	defer p.poolLock.Unlock()
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

func (p *Process) reportPool() {
	p.poolLock.RLock()
	defer p.poolLock.RUnlock()
	if len(p.smtpPool) == 0 {
		log.Debugf("no smtp connection")
		return
	}
	for _, client := range p.smtpPool {
		log.Infof("smtp connection (server/domains/lastsent): %s/%s/%s", client.Relay, strings.Join(client.Domains, ","), time.Since(client.LastSent).String())
	}
}

func (p *Process) Handle(msg message.Message) (string, bool, error) {
	// id the message
	if len(msg.Id) == 0 {
		msg.Id = uuid.NewString()
	}
	// check that message is signed
	if !msg.Signed() {
		log.Warnf("%s: message is not signed", msg.Id)
	}
	// update recipients following rules
	p.rules.UpdateMessage(&msg)
	// if destination doesn't go anywhere return an error
	if len(msg.To) == 0 {
		log.Infof("%s: message has no destination", msg.Id)
		return "", true, fmt.Errorf("no recipients")
	}
	log.Debugf("%s: mapping smtp relays to send to", msg.Id)
	// lock the pool
	p.poolLock.Lock()
	defer p.poolLock.Unlock()
	// get targeted domains
	domains := msg.Domains()
	// status on connections
	log.Debugf("mx statuses")
	for i := range p.smtpPool {
		state := "disconnected"
		if p.smtpPool[i].Connected {
			state = "connected"
		}
		log.Debugf("mx %s is %s", p.smtpPool[i].Relay, state)
	}
	// list the pools to run the message to
	targetSmtp := []int{}
	// match domains against existing smtp connections
	found := false
	matchedDomains := []int{}
	for i := range p.smtpPool {
		for _, smtpDomain := range p.smtpPool[i].Domains {
			for j, msgDomain := range domains {
				if smtpDomain == msgDomain {
					found = false
					for _, k := range targetSmtp {
						if i == k {
							found = true
							break
						}
					}
					if !found {
						targetSmtp = append(targetSmtp, i)
					}
					matchedDomains = append(matchedDomains, j)
				}
			}
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(matchedDomains)))
	log.Debugf("%s: domains: %s", msg.Id, strings.Join(domains, ", "))
	log.Debugf("%s: matched domains index: %v", msg.Id, matchedDomains)
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
			log.Infof("%s: could not find mx for %s", msg.Id, domain)
		}
		// match mail exchanger against pool
		targetFound := false
		for _, mx := range mxs {
			for i := range p.smtpPool {
				if mx.Host == p.smtpPool[i].Relay {
					// update pool data with domain
					p.smtpPool[i].Domains = append(p.smtpPool[i].Domains, domain)
					found = false
					for _, j := range targetSmtp {
						if i == j {
							found = true
							break
						}
					}
					if !found {
						targetSmtp = append(targetSmtp, i)
					}
					targetFound = true
				}
			}
		}
		if targetFound {
			continue
		}
		// domain not found let's add a smtp connection
		added := false
		for _, mx := range mxs {
			// create smtp client
			client := &client.SmtpClient{
				Relay:    mx.Host,
				Domains:  []string{domain},
				Hostname: p.Hostname,
				LastSent: time.Now(),
			}
			// connect to server
			err = client.Connect()
			if err != nil {
				log.Infof("%s: could not connect to mx %s for %s", msg.Id, mx.Host, domain)
				continue
			}
			// present ourselves
			err = client.Helo()
			if err != nil {
				log.Infof("%s: not welcomed by mx %s for %s", msg.Id, mx.Host, domain)
				continue
			}
			// handle tls
			if client.TlsSupported {
				err = client.StartTLS()
				if err != nil {
					log.Infof("%s: tls fail at mx %s for %s", msg.Id, mx.Host, domain)
					continue
				}
				// re hello
				err = client.Helo()
				if err != nil {
					log.Infof("%s: not welcomed by mx %s for %s", msg.Id, mx.Host, domain)
					continue
				}
			}
			// add client to the pool
			p.smtpPool = append(p.smtpPool, *client)
			targetSmtp = append(targetSmtp, len(p.smtpPool)-1)
			added = true
			log.Infof("%s: connected to mx %s for %s", msg.Id, mx.Host, domain)
			break
		}
		if !added {
			log.Infof("%s: could not connect to any mx for %s", msg.Id, domain)
		}
	}
	// create a waitgroup for client sends
	var wg sync.WaitGroup
	wg.Add(len(targetSmtp))
	// channel to recieve results
	okChan := make(chan bool, len(targetSmtp))
	// start gofunc to send messages
	for _, i := range targetSmtp {
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
	log.Debugf("mx statuses")
	for i := range p.smtpPool {
		state := "disconnected"
		if p.smtpPool[i].Connected {
			state = "connected"
		}
		log.Debugf("mx %s is %s", p.smtpPool[i].Relay, state)
	}
	// return result
	if !result {
		return msg.Id, false, fmt.Errorf("could not send message to all relays")
	}
	return msg.Id, false, nil
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
