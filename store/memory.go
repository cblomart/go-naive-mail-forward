package store

import (
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/rules"
	"fmt"
	"log"
	"sync"
)

type Memory struct {
	messages map[string]message.Message
	lock     *sync.Mutex
	rules    *rules.Rules
}

func NewMemoryStore(rules *rules.Rules) Memory {
	return Memory{
		lock:     &sync.Mutex{},
		messages: make(map[string]message.Message),
		rules:    rules,
	}
}

func (m Memory) Add(msg message.Message) (string, error) {
	if len(msg.Id) == 0 {
		log.Printf("storage - rejecting unidentified message")
		return "", fmt.Errorf("unidentified message recieved")
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	// updating to from rules
	m.rules.UpdateMessage(&msg)
	m.messages[msg.Id] = msg
	log.Printf("storage - added message %s", msg.Id)
	return msg.Id, nil
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

func (m Memory) GetIds() ([]string, error) {
	ids := make([]string, len(m.messages))
	i := 0
	for id := range m.messages {
		ids[i] = id
		i++
	}
	return ids, nil
}

func (m Memory) Type() string {
	return "memory"
}
