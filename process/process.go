package process

import (
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/rules"
	"cblomart/go-naive-mail-forward/store"
	"fmt"
)

type Process struct {
	rules *rules.Rules
	Store store.Store
}

func NewProcessor(storeType string, processRules *rules.Rules) (*Process, error) {
	s, err := store.NewStore(storeType)
	if err != nil {
		return nil, fmt.Errorf("cannot create storage")
	}
	return &Process{
		rules: processRules,
		Store: s,
	}, nil
}

func (p *Process) Add(msg message.Message) (string, error) {
	p.rules.UpdateMessage(&msg)
	return p.Store.Add(msg)
}
