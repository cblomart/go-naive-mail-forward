package store

import (
	"cblomart/go-naive-mail-forward/message"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/google/uuid"
)

type Memory struct {
	messages map[string]message.Message
	infos    map[string][]string
	lock     *sync.Mutex
}

func NewMemoryStore() Memory {
	return Memory{
		lock:     &sync.Mutex{},
		messages: make(map[string]message.Message),
		infos:    make(map[string][]string),
	}
}

func (m Memory) Add(msg message.Message) (string, error) {
	id := uuid.New().String()
	m.lock.Lock()
	defer m.lock.Unlock()
	m.messages[id] = msg
	if _, ok := m.infos[msg.MX]; !ok {
		m.infos[msg.MX] = make([]string, 0)
	}
	m.infos[msg.MX] = append(m.infos[msg.MX], id)
	log.Printf("storage - added message %s", id)
	var sb strings.Builder
	for mx, ids := range m.infos {
		sb.WriteString(mx)
		sb.WriteString(fmt.Sprintf("[%d] ", len(ids)))
	}
	log.Printf("storage - mx stats: %s", strings.TrimSpace(sb.String()))
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
