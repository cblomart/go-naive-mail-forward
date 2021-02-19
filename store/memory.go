package store

import (
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/rules"
	"fmt"
	"log"
	"sync"

	"github.com/google/uuid"
)

type Memory struct {
	messages map[string]message.Message
	infos    map[string][]string
	lock     *sync.Mutex
	rules    *rules.Rules
}

func NewMemoryStore(rules *rules.Rules) Memory {
	return Memory{
		lock:     &sync.Mutex{},
		messages: make(map[string]message.Message),
		infos:    make(map[string][]string),
		rules:    rules,
	}
}

func (m Memory) Add(msg message.Message) (string, error) {
	id := uuid.New().String()
	m.lock.Lock()
	defer m.lock.Unlock()
	// updating to from rules
	m.rules.UpdateMessage(&msg)
	m.messages[id] = msg
	log.Printf("storage - added message %s", id)
	return id, nil
}

func (m Memory) Lock() {
	m.lock.Lock()
}

func (m Memory) Unlock() {
	m.lock.Unlock()
}

func (m Memory) Remove(id string) error {
	delete(m.messages, id)
	return nil
}

func (m Memory) Get(id string) (*message.Message, error) {
	if msg, ok := m.messages[id]; ok {
		return &msg, nil
	}
	return nil, fmt.Errorf("Message not found")
}

func (m Memory) GetInfos() (map[string][]string, error) {
	return m.infos, nil
}

func (m Memory) Type() string {
	return "memory"
}
