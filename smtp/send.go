package smtp

import (
	"cblomart/go-naive-mail-forward/message"
	"cblomart/go-naive-mail-forward/store"
	"log"
	"time"
)

func Send(store store.Store) {
	log.Printf("smtp - sending stored messages")
	store.Lock()
	defer store.Unlock()
	// select the top relay to send to and grab all the messages for it
	relay, messages, err := calculateQueue(store)
	if err != nil {
		log.Printf("smtp - failed to select relay/messages: %s", err.Error())
		return
	}
	log.Printf("smtp - sending %d messages to %s", len(messages), relay)
}

func calculateQueue(store store.Store) (string, []message.Message, error) {
	start := time.Now()
	msgIds, err := store.GetIds()
	if err != nil {
		return "", nil, err
	}
	if len(msgIds) == 0 {
		log.Printf("smtp - nothing to send")
		return "", nil, nil
	}
	msgs := make([]message.Message, len(msgIds))
	// scoring relays
	mxScore := map[string]int{}
	max := 0
	for i, id := range msgIds {
		msg, err := store.Get(id)
		if err != nil {
			log.Printf("smtp - send: couldn't get message %s", id)
			continue
		}
		msgs[i] = *msg
		for _, to := range msg.To {
			for _, toMx := range to.MX {
				if _, ok := mxScore[toMx]; !ok {
					mxScore[toMx] = 0
				}
				mxScore[toMx]++
				if max < mxScore[toMx] {
					max = mxScore[toMx]
				}
			}
		}
	}
	// get the top socred relay
	relay := ""
	for currentRelay, score := range mxScore {
		if score == max {
			relay = currentRelay
			break
		}
	}
	// get the messages that can go trough this relay
	relayMsgs := make([]message.Message, 0)
	for _, msg := range msgs {
		selected := false
		for _, to := range msg.To {
			for _, mx := range to.MX {
				if mx == relay {
					relayMsgs = append(relayMsgs, msg)
					selected = true
					break
				}
			}
			if selected {
				break
			}
		}
	}
	diff := time.Now().Sub(start)
	log.Printf("smtp - selecting relay/messages took %s", diff.String())
	return relay, relayMsgs, nil
}
