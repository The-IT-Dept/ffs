package notify

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TimeRange is a range of minutes within a day, "HH:MM" to "HH:MM", start included and end
// excluded. EndTime may be "24:00".
type TimeRange struct{ StartTime, EndTime string }

// TimeInterval follows Alertmanager's time_intervals: it matches when every non-empty field matches.
// Weekdays are names or 0-6 with Sunday 0, as in cron ("monday", "1", ranges "monday:friday" or
// "1:5"; a range may wrap past the end of the week, so "saturday:sunday" is the weekend). Months
// are names or 1-12, DaysOfMonth 1-31 or counted from the month's end as -1 to -31, Years numbers;
// all take inclusive "a:b" ranges. Location is an IANA zone, UTC when empty.
type TimeInterval struct {
	Times                                []TimeRange
	Weekdays, DaysOfMonth, Months, Years []string
	Location                             string
}

// Validate reports the first field that does not parse.
func (ti TimeInterval) Validate() error {
	_, err := ti.parse()
	return err
}

// QuietUntil reports whether t falls in any of ivs and, if so, the first whole minute after t that
// falls in none of them, searching up to 8 days ahead. Invalid intervals never match.
func QuietUntil(ivs []TimeInterval, t time.Time) (until time.Time, active bool) {
	parsed := make([]interval, 0, len(ivs))
	for _, ti := range ivs {
		if iv, err := ti.parse(); err == nil {
			parsed = append(parsed, iv)
		}
	}
	quiet := func(at time.Time) bool {
		for _, iv := range parsed {
			if iv.contains(at) {
				return true
			}
		}
		return false
	}
	if !quiet(t) {
		return time.Time{}, false
	}
	m := t.Truncate(time.Minute)
	limit := m.Add(8 * 24 * time.Hour)
	for m = m.Add(time.Minute); m.Before(limit); m = m.Add(time.Minute) {
		if !quiet(m) {
			return m, true
		}
	}
	return limit, true
}

// span is an inclusive range of values; for times of day, minutes with hi excluded.
type span struct{ lo, hi int }

type interval struct {
	times, weekdays, days, months, years []span
	loc                                  *time.Location
}

func (iv interval) contains(t time.Time) bool {
	t = t.In(iv.loc)
	if len(iv.times) > 0 && !anySpan(iv.times, func(s span) bool {
		m := t.Hour()*60 + t.Minute()
		return m >= s.lo && m < s.hi
	}) {
		return false
	}
	if len(iv.weekdays) > 0 && !anySpan(iv.weekdays, func(s span) bool { return inCycle(int(t.Weekday()), s) }) {
		return false
	}
	if len(iv.days) > 0 && !anySpan(iv.days, func(s span) bool { return inMonthDays(t, s) }) {
		return false
	}
	if len(iv.months) > 0 && !anySpan(iv.months, func(s span) bool { return int(t.Month()) >= s.lo && int(t.Month()) <= s.hi }) {
		return false
	}
	if len(iv.years) > 0 && !anySpan(iv.years, func(s span) bool { return t.Year() >= s.lo && t.Year() <= s.hi }) {
		return false
	}
	return true
}

func anySpan(ss []span, f func(span) bool) bool {
	for _, s := range ss {
		if f(s) {
			return true
		}
	}
	return false
}

// inCycle reports whether weekday v is in s, which wraps past Saturday when lo > hi.
func inCycle(v int, s span) bool {
	if s.lo <= s.hi {
		return v >= s.lo && v <= s.hi
	}
	return v >= s.lo || v <= s.hi
}

// inMonthDays matches Alertmanager: negative days count back from the month's end, a range that
// starts after the month's end never matches, and the end is clamped to the month.
func inMonthDays(t time.Time, s span) bool {
	n := time.Date(t.Year(), t.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
	lo, hi := s.lo, s.hi
	if lo < 0 {
		lo = n + lo + 1
	}
	if hi < 0 {
		hi = n + hi + 1
	}
	if lo > n {
		return false
	}
	hi = min(hi, n)
	return t.Day() >= lo && t.Day() <= hi
}

func (ti TimeInterval) parse() (interval, error) {
	var iv interval
	for _, tr := range ti.Times {
		lo, err := parseClock(tr.StartTime, false)
		if err != nil {
			return interval{}, err
		}
		hi, err := parseClock(tr.EndTime, true)
		if err != nil {
			return interval{}, err
		}
		if lo >= hi {
			return interval{}, fmt.Errorf("time range %s-%s: the start must be before the end", tr.StartTime, tr.EndTime)
		}
		iv.times = append(iv.times, span{lo, hi})
	}
	var err error
	if iv.weekdays, err = parseSpans("weekday", ti.Weekdays, weekday, true); err != nil {
		return interval{}, err
	}
	if iv.days, err = parseDays(ti.DaysOfMonth); err != nil {
		return interval{}, err
	}
	if iv.months, err = parseSpans("month", ti.Months, month, false); err != nil {
		return interval{}, err
	}
	if iv.years, err = parseSpans("year", ti.Years, year, false); err != nil {
		return interval{}, err
	}
	iv.loc = time.UTC
	if ti.Location != "" {
		if iv.loc, err = time.LoadLocation(ti.Location); err != nil {
			return interval{}, fmt.Errorf("location %q: unknown time zone", ti.Location)
		}
	}
	return iv, nil
}

// parseClock reads "HH:MM" as minutes since midnight; "24:00" only as an end.
func parseClock(s string, end bool) (int, error) {
	h, m, ok := strings.Cut(s, ":")
	if ok && len(h) == 2 && len(m) == 2 {
		hh, herr := strconv.Atoi(h)
		mm, merr := strconv.Atoi(m)
		switch {
		case herr != nil || merr != nil:
		case end && hh == 24 && mm == 0:
			return 24 * 60, nil
		case hh >= 0 && hh <= 23 && mm >= 0 && mm <= 59:
			return hh*60 + mm, nil
		}
	}
	return 0, fmt.Errorf("time %q: want HH:MM from 00:00 to 23:59 (24:00 as an end)", s)
}

// parseSpans reads values or "a:b" ranges with value. A range may run backwards only when cyclic.
func parseSpans(what string, in []string, value func(string) (int, bool), cyclic bool) ([]span, error) {
	out := make([]span, 0, len(in))
	for _, s := range in {
		a, b, isRange := strings.Cut(strings.ToLower(strings.TrimSpace(s)), ":")
		if !isRange {
			b = a
		}
		lo, okLo := value(a)
		hi, okHi := value(b)
		if !okLo || !okHi {
			return nil, fmt.Errorf("%s %q: not recognised", what, s)
		}
		if lo > hi && !cyclic {
			return nil, fmt.Errorf("%s range %q: the start must not be after the end", what, s)
		}
		out = append(out, span{lo, hi})
	}
	return out, nil
}

var errDay = errors.New("want 1 to 31, or -1 to -31 counted from the end of the month")

// parseDays reads days of the month: 1..31 or -31..-1, singly or as "a:b" ranges. As in
// Alertmanager, a range's start must not be after its end when both are read in a 31-day month.
func parseDays(in []string) ([]span, error) {
	out := make([]span, 0, len(in))
	for _, s := range in {
		a, b, isRange := strings.Cut(strings.TrimSpace(s), ":")
		if !isRange {
			b = a
		}
		lo, errLo := strconv.Atoi(a)
		hi, errHi := strconv.Atoi(b)
		if errLo != nil || errHi != nil || !validDay(lo) || !validDay(hi) {
			return nil, fmt.Errorf("day of month %q: %w", s, errDay)
		}
		if absDay(lo) > absDay(hi) {
			return nil, fmt.Errorf("day of month range %q: the start must not be after the end", s)
		}
		out = append(out, span{lo, hi})
	}
	return out, nil
}

func validDay(d int) bool { return d != 0 && d >= -31 && d <= 31 }

// absDay places d in a 31-day month.
func absDay(d int) int {
	if d < 0 {
		return 32 + d
	}
	return d
}

var weekdays = map[string]int{"sunday": 0, "monday": 1, "tuesday": 2, "wednesday": 3, "thursday": 4, "friday": 5, "saturday": 6}

// weekday reads a weekday name or its number, 0 (Sunday) to 6 (Saturday) as in cron and Go's
// time.Weekday.
func weekday(s string) (int, bool) {
	if v, ok := weekdays[s]; ok {
		return v, true
	}
	v, err := strconv.Atoi(s)
	return v, err == nil && v >= 0 && v <= 6
}

var months = map[string]int{"january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6, "july": 7,
	"august": 8, "september": 9, "october": 10, "november": 11, "december": 12}

func month(s string) (int, bool) {
	if v, ok := months[s]; ok {
		return v, true
	}
	v, err := strconv.Atoi(s)
	return v, err == nil && v >= 1 && v <= 12
}

func year(s string) (int, bool) {
	v, err := strconv.Atoi(s)
	return v, err == nil && v >= 1 && v <= 9999
}
