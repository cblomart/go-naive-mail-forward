package store

import (
	"cblomart/go-naive-mail-forward/message"
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

func NewStore(storeType string) (Store, error) {
	switch storeType {
	case "memory":
		return NewMemoryStore(), nil
	}
	return nil, fmt.Errorf("store type not found")
}
