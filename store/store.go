package store

import (
	"cblomart/go-naive-mail-forward/message"
	"fmt"
)

type Store interface {
	Add(msg *message.Message) (string, error)
	Remove(id string) error
}

func NewStore(storeType string) (Store, error) {
	switch storeType {
	case "memory":
		return Memory{}, nil
	}
	return nil, fmt.Errorf("store type not found")
}
