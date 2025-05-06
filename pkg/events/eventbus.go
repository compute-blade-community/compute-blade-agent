package events

import (
	"sync"
)

// EventBus is a simple event bus with topic-based publish/subscribe.
// This is, by no means, a performant or complete implementation but for the scope of this project more than sufficient
type EventBus interface {
	Publish(topic string, message any)
	Subscribe(topic string, bufSize int, filter func(any) bool) Subscriber
}

type Subscriber interface {
	C() <-chan any
	Unsubscribe()
}

type eventBus struct {
	subscribers map[string]map[*subscriber]func(any) bool
	mu          sync.Mutex
}

type subscriber struct {
	mu     sync.Mutex
	ch     chan any
	closed bool
}

func MatchAll(_ any) bool {
	return true
}

// New returns an initialized EventBus.
func New() EventBus {
	return &eventBus{
		subscribers: make(map[string]map[*subscriber]func(any) bool),
	}
}

// Publish a message to a topic (best-effort). Subscribers with a full receive queue are dropped.
func (eb *eventBus) Publish(topic string, message any) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if eb.subscribers[topic] == nil {
		return
	}

	if subs, ok := eb.subscribers[topic]; ok {
		for sub, filter := range subs {
			sub.mu.Lock()
			// Clean up closed subscribers
			if sub.closed {
				delete(eb.subscribers[topic], sub)
				continue
			}

			if filter(message) {
				// Try to send message, but don't block
				select {
				case sub.ch <- message:
				default:
				}
			}

			sub.mu.Unlock()
		}
	}
}

// Subscribe to a topic with a filter function. Returns a channel with given buffer size.
func (eb *eventBus) Subscribe(topic string, bufSize int, filter func(any) bool) Subscriber {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	ch := make(chan any, bufSize)

	sub := &subscriber{
		ch:     ch,
		closed: false,
	}

	if _, ok := eb.subscribers[topic]; !ok {
		eb.subscribers[topic] = make(map[*subscriber]func(any) bool)
	}

	eb.subscribers[topic][sub] = filter

	return sub
}

func (s *subscriber) C() <-chan any {
	return s.ch
}

func (s *subscriber) Unsubscribe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	close(s.ch)
	s.closed = true
}
