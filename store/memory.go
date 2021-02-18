package store

import (
	"cblomart/go-naive-mail-forward/message"
	"fmt"
	"sync"
)

type Memory struct {
	messages map[string]message.Message
	lock     *sync.RWMutex
}

func (m Memory) Add(msg *message.Message) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (m Memory) Remove(id string) error {
	return fmt.Errorf("not implemented")
}
