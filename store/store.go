package store

import (
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/rules"
	"fmt"
)

type Store interface {
	Lock()
	Unlock()
	Add(msg message.Message) (string, error)
	Remove(id string) error
	Get(id string) (*message.Message, error)
	GetIds() ([]string, error)
	Type() string
}

func NewStore(storeType string, rules *rules.Rules) (Store, error) {
	switch storeType {
	case "memory":
		return NewMemoryStore(rules), nil
	}
	return nil, fmt.Errorf("store type not found")
}
