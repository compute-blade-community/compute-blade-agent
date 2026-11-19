package ledengine

import (
	"fmt"
	"reflect"
	"sync"
)

// Stack layers several named indicator patterns on top of a base pattern for a single LED.
//
// Every layer has a priority. Of all active layers, the one with the highest priority is shown; if no layer is active,
// the base pattern is shown. This lets independent conditions (identify, critical mode, a stalled fan, ...) share one
// LED without overwriting each other: when the highest layer is deactivated, the next one shows up again.
type Stack struct {
	mu      sync.Mutex
	engine  LedEngine
	base    BlinkPattern
	layers  map[string]*stackLayer
	current *BlinkPattern
}

type stackLayer struct {
	priority int
	pattern  BlinkPattern
	active   bool
}

// NewStack creates a Stack driving the given engine and shows the base pattern.
func NewStack(engine LedEngine, base BlinkPattern) (*Stack, error) {
	s := &Stack{
		engine: engine,
		base:   base,
		layers: make(map[string]*stackLayer),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s, s.apply()
}

// Define registers (or replaces) a layer. Redefining an active layer keeps it active.
func (s *Stack) Define(name string, priority int, pattern BlinkPattern) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	active := false
	if existing, ok := s.layers[name]; ok {
		active = existing.active
	}
	s.layers[name] = &stackLayer{priority: priority, pattern: pattern, active: active}
	return s.apply()
}

// Defined reports whether a layer with the given name exists.
func (s *Stack) Defined(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.layers[name]
	return ok
}

// Activate turns a layer on.
func (s *Stack) Activate(name string) error {
	return s.setActive(name, true)
}

// Deactivate turns a layer off.
func (s *Stack) Deactivate(name string) error {
	return s.setActive(name, false)
}

// SetBase replaces the pattern shown when no layer is active.
func (s *Stack) SetBase(pattern BlinkPattern) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.base = pattern
	return s.apply()
}

// Shown returns the name of the layer currently shown, or an empty string if the base pattern is shown.
func (s *Stack) Shown() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	name, _ := s.top()
	return name
}

func (s *Stack) setActive(name string, active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	layer, ok := s.layers[name]
	if !ok {
		return fmt.Errorf("unknown LED layer %q", name)
	}
	if layer.active == active {
		return nil
	}
	layer.active = active
	return s.apply()
}

// top returns the highest-priority active layer. Equal priorities are broken by name to stay deterministic.
func (s *Stack) top() (string, *stackLayer) {
	var (
		bestName  string
		bestLayer *stackLayer
	)
	for name, layer := range s.layers {
		if !layer.active {
			continue
		}
		if bestLayer == nil ||
			layer.priority > bestLayer.priority ||
			(layer.priority == bestLayer.priority && name < bestName) {
			bestName, bestLayer = name, layer
		}
	}
	return bestName, bestLayer
}

// apply pushes the pattern that should be shown to the engine, unless it is already showing. Restarting an identical
// pattern would make blinking patterns stutter. Must be called with s.mu held.
func (s *Stack) apply() error {
	pattern := s.base
	if _, layer := s.top(); layer != nil {
		pattern = layer.pattern
	}

	if s.current != nil && reflect.DeepEqual(*s.current, pattern) {
		return nil
	}

	if err := s.engine.SetPattern(pattern); err != nil {
		return err
	}
	s.current = &pattern
	return nil
}
