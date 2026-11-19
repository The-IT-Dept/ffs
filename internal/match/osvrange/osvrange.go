// Package osvrange evaluates the events of one OSV range against a version: the OSV schema's
// introduced / fixed / last_affected walk. How versions compare is the caller's business, so the
// same walk serves OSV ecosystem ranges and the extracted ranges of upstream GIT records.
package osvrange

import "slices"

// Event is one range event. Exactly one field is set; an event with none is ignored.
type Event struct{ Introduced, Fixed, LastAffected string }

// Result is what Evaluate found.
type Result struct {
	// Affected reports whether the version lies in an affected interval of the range.
	Affected bool
	// Fixed holds the smallest Fixed event above the version, if the range has one.
	Fixed []string
	// EndsInLastAffected reports, for an affected version, that the interval holding it is closed
	// by a last_affected event rather than a fixed one.
	EndsInLastAffected bool
}

// Evaluate sorts events ascending with compare ("0" lowest) and walks them: an introduced event at
// or below version opens an affected interval, a fixed event at or below version closes it, and a
// last_affected event below version closes it. compare(a, b) returns a negative number, zero or a
// positive number as a is below, equal to or above b; it is never called with an introduced "0".
func Evaluate(events []Event, compare func(a, b string) int, version string) Result {
	sorted := make([]Event, 0, len(events))
	for _, e := range events {
		if key(e) != "" {
			sorted = append(sorted, e)
		}
	}
	slices.SortStableFunc(sorted, func(a, b Event) int {
		ka, kb := key(a), key(b)
		switch {
		case ka == kb:
			return 0
		case ka == "0":
			return -1
		case kb == "0":
			return 1
		}
		return compare(ka, kb)
	})

	var r Result
	for _, e := range sorted {
		switch {
		case e.Introduced != "":
			if e.Introduced == "0" || compare(version, e.Introduced) >= 0 {
				r.Affected = true
			}
		case e.Fixed != "":
			if compare(version, e.Fixed) >= 0 {
				r.Affected = false
			}
		case e.LastAffected != "":
			if compare(version, e.LastAffected) > 0 {
				r.Affected = false
			}
		}
	}
	for _, e := range sorted {
		if e.Fixed != "" && compare(version, e.Fixed) < 0 {
			r.Fixed = []string{e.Fixed}
			break
		}
	}
	if r.Affected {
		// The interval holding version ends at the first limit event above it.
		for _, e := range sorted {
			if e.Fixed != "" && compare(version, e.Fixed) < 0 {
				break
			}
			if e.LastAffected != "" && compare(version, e.LastAffected) <= 0 {
				r.EndsInLastAffected = true
				break
			}
		}
	}
	return r
}

// key returns the version an event sits at, or "" for an empty event.
func key(e Event) string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	}
	return e.LastAffected
}
