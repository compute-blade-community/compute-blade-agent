package events_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/uptime-industries/compute-blade-agent/pkg/events"
)

func TestEventBusManySubscribers(t *testing.T) {
	eb := events.New()

	// Create a channel and subscribe to a topic without a filter
	sub0 := eb.Subscribe("topic0", 2, events.MatchAll)
	assert.Equal(t, cap(sub0.C()), 2)
	assert.Equal(t, len(sub0.C()), 0)
	defer sub0.Unsubscribe()

	// Create a channel and subscribe to a topic with a filter
	sub1 := eb.Subscribe("topic0", 2, func(msg any) bool {
		return msg.(int) > 5
	})
	assert.Equal(t, cap(sub1.C()), 2)
	assert.Equal(t, len(sub1.C()), 0)
	defer sub1.Unsubscribe()

	// Create a channel and subscribe to another topic
	sub2 := eb.Subscribe("topic1", 1, events.MatchAll)
	assert.Equal(t, cap(sub2.C()), 1)
	assert.Equal(t, len(sub2.C()), 0)
	defer sub2.Unsubscribe()

	sub3 := eb.Subscribe("topic1", 0, events.MatchAll)
	assert.Equal(t, cap(sub3.C()), 0)
	assert.Equal(t, len(sub3.C()), 0)
	defer sub3.Unsubscribe()

	// Publish some messages
	eb.Publish("topic0", 10)
	eb.Publish("topic0", 4)
	eb.Publish("topic1", "Hello, World!")

	// Assert received messages
	assert.Equal(t, len(sub0.C()), 2)
	assert.Equal(t, <-sub0.C(), 10)
	assert.Equal(t, <-sub0.C(), 4)

	assert.Equal(t, len(sub1.C()), 1)
	assert.Equal(t, <-sub1.C(), 10)

	assert.Equal(t, len(sub2.C()), 1)
	assert.Equal(t, <-sub2.C(), "Hello, World!")

	// sub3 has no buffer, so it should be empty as there's been no consumer at time of publishing
	assert.Equal(t, len(sub3.C()), 0)
}

func TestUnsubscribe(t *testing.T) {
	eb := events.New()

	// Create a channel and subscribe to a topic
	sub := eb.Subscribe("topic", 2, events.MatchAll)

	// Unsubscribe from the topic
	sub.Unsubscribe()

	// Try to publish a message after unsubscribing
	eb.Publish("topic", "This message should not be received")

	// Assert that the channel is closed
	_, ok := <-sub.C()
	assert.False(t, ok, "Unsubscribed channel should be closed")

}
