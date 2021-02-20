package process

import (
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/rules"
	"cblomart/go-naive-mail-forward/smtp/smtpclient"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Process struct {
	smtpPool []smtpclient.SmtpClient
	poolLock sync.Mutex
	rules    *rules.Rules
	Hostname string
	Debug    bool
}

func NewProcessor(hostname string, processRules *rules.Rules, debug bool) (*Process, error) {
	process := &Process{
		smtpPool: []smtpclient.SmtpClient{},
		poolLock: sync.Mutex{},
		rules:    processRules,
		Debug:    debug,
		Hostname: hostname,
	}
	// start pool management
	go process.ManagePools()
	return process, nil
}

func (p *Process) ManagePools() {
	log.Printf("process - manage smtp connection pool (keepalive: 4m, nosendtimeout: 30m)")
	// check every keepalive
	ticker := time.NewTicker(4 * time.Minute)
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

func remove(s []int, i int) []int {
	s[i] = s[len(s)-1]
	// We do not need to put s[i] at the end, as it will be discarded anyway
	return s[:len(s)-1]
}

func (p *Process) checkPools() {
	p.poolLock.Lock()
	defer p.poolLock.Unlock()
	// clean current pool
	p.cleanPool()
	// keepalive current pool
	p.keepAlivePool()
	// clean lingering connections that may have tripped
	p.cleanPool()
	// now we should be good
	p.reportPool()
}

func (p *Process) cleanPool() {
	// suppose lock was already aquired
	minLastSent := time.Now().Add(-30 * time.Minute)
	// clean disconnected or pools that did not send mails recently
	toRemove := []int{}
	for i, _ := range p.smtpPool {
		if !p.smtpPool[i].Connected || p.smtpPool[i].LastSent.Before(minLastSent) {
			toRemove = append(toRemove, i)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(toRemove)))
	for _, i := range toRemove {
		if p.smtpPool[i].Connected {
			p.smtpPool[i].Close()
		}
		// set element to remove to the last one
		p.smtpPool[i] = p.smtpPool[len(p.smtpPool)-1]
		// remove the last element of the slice
		p.smtpPool = p.smtpPool[:len(p.smtpPool)-1]
	}
}

func (p *Process) keepAlivePool() {
	for _, client := range p.smtpPool {
		if client.Connected {
			client.Noop()
		}
	}
}

func (p *Process) reportPool() {
	for _, client := range p.smtpPool {
		log.Printf("process - smtp connection (server/domains/lastsent): %s/%s/%s", client.Relay, strings.Join(client.Domains, ","), time.Now().Sub(client.LastSent).String())
	}
}

func (p *Process) Handle(msg message.Message) (string, error) {
	// id the message
	if len(msg.Id) == 0 {
		msg.Id = uuid.NewString()
	}
	// check that message is signed
	if !msg.Signed() {
		log.Printf("process - %s: message is not signed", msg.Id)
		return "", fmt.Errorf("message is not signed")
	}
	// update recipients following rules
	p.rules.UpdateMessage(&msg)
	log.Printf("process - %s: mapping smtp relays to send to", msg.Id)
	// lock the pool
	p.poolLock.Lock()
	defer p.poolLock.Unlock()
	// get targeted domains
	domains := msg.Domains()
	// list the pools to run the message to
	targetSmtp := []int{}
	// match domains against existing smtp connections
	found := false
	matchedDomains := []int{}
	for i, _ := range p.smtpPool {
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
	if p.Debug {
		log.Printf("process - %s: domains: %s", msg.Id, strings.Join(domains, ", "))
		log.Printf("process - %s: matched domains index: %v", msg.Id, matchedDomains)
	}
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
			log.Printf("process - %s: could not find mx for %s", msg.Id, domain)
		}
		// match mail exchanger against pool
		targetFound := false
		for _, mx := range mxs {
			for i, _ := range p.smtpPool {
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
			client := &smtpclient.SmtpClient{
				Relay:    mx.Host,
				Domains:  []string{domain},
				Debug:    p.Debug,
				Hostname: p.Hostname,
			}
			// connect to server
			err = client.Connect()
			if err != nil {
				log.Printf("process - %s: could not connect to mx %s for %s", msg.Id, mx.Host, domain)
				continue
			}
			// present ourselves
			err = client.Helo()
			if err != nil {
				log.Printf("process - %s: not welcomed by mx %s for %s", msg.Id, mx.Host, domain)
				continue
			}
			// add client to the pool
			p.smtpPool = append(p.smtpPool, *client)
			targetSmtp = append(targetSmtp, len(p.smtpPool)-1)
			added = true
			break
		}
		if !added {
			log.Printf("process - %s: could not connect to any mx for %s", msg.Id, domain)
		}
	}
	// create a waitgroup for client sends
	var wg sync.WaitGroup
	wg.Add(len(targetSmtp))
	// channel to recieve results
	okChan := make(chan bool, len(targetSmtp))
	// start gofunc to send messages
	for _, i := range targetSmtp {
		client := p.smtpPool[i]
		go func() {
			defer wg.Done()
			err := client.SendMessage(msg)
			if err != nil {
				log.Printf("process - %s: could not send via %s: %s", msg.Id, p.smtpPool[i].Relay, err.Error())
				okChan <- false
				return
			}
			okChan <- true
		}()
	}
	// wait for messages to be sent
	wg.Wait()
	// evaluate result
	result := false
	for res := range okChan {
		if res {
			result = true
		}
	}
	// return result
	if !result {
		return msg.Id, fmt.Errorf("could not send message to all relays")
	}
	return msg.Id, nil
}
