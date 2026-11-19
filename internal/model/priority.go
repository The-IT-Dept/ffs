package model

import (
	"fmt"
	"strings"
)

// Priority is the ffs-assigned urgency of a finding.
type Priority int

const (
	PriorityNone Priority = iota
	PriorityLow
	PriorityMedium
	PriorityHigh
	PriorityUrgent
)

var priorityNames = [...]string{"", "low", "medium", "high", "urgent"}

// String returns the lowercase name, or "" for PriorityNone.
func (p Priority) String() string {
	if p < 0 || int(p) >= len(priorityNames) {
		return ""
	}
	return priorityNames[p]
}

// ParsePriority parses low, medium, high or urgent, ignoring case and surrounding space.
func ParsePriority(s string) (Priority, error) {
	n := strings.ToLower(strings.TrimSpace(s))
	for i := PriorityLow; i <= PriorityUrgent; i++ {
		if priorityNames[i] == n {
			return i, nil
		}
	}
	return PriorityNone, fmt.Errorf("invalid priority %q: want low, medium, high or urgent", s)
}

// MarshalText implements encoding.TextMarshaler.
func (p Priority) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler. "" maps to PriorityNone.
func (p *Priority) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*p = PriorityNone
		return nil
	}
	v, err := ParsePriority(string(b))
	if err != nil {
		return err
	}
	*p = v
	return nil
}

// Severity is an advisory severity.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityNegligible
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{"unknown", "negligible", "low", "medium", "high", "critical"}

// String returns the lowercase name.
func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// ParseSeverity is tolerant: vendor synonyms map to the nearest level and anything unrecognised is Unknown.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high", "important":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "negligible", "unimportant", "none":
		return SeverityNegligible
	}
	return SeverityUnknown
}

// MarshalText implements encoding.TextMarshaler.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Severity) UnmarshalText(b []byte) error {
	*s = ParseSeverity(string(b))
	return nil
}
