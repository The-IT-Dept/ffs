package notify_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/notify"
)

func assertUntil(t *testing.T, ivs []notify.TimeInterval, at, want time.Time) {
	t.Helper()
	until, active := notify.QuietUntil(ivs, at)
	require.True(t, active, "quiet at %s", at)
	assert.Equal(t, want.UTC(), until.UTC())
}

func assertNotQuiet(t *testing.T, ivs []notify.TimeInterval, at time.Time) {
	t.Helper()
	until, active := notify.QuietUntil(ivs, at)
	assert.False(t, active, "quiet at %s", at)
	assert.True(t, until.IsZero())
}

func TestQuietUntil_WindowAcrossMidnight(t *testing.T) {
	sydney, err := time.LoadLocation("Australia/Sydney")
	require.NoError(t, err)
	ivs := []notify.TimeInterval{{Times: []notify.TimeRange{{StartTime: "22:00", EndTime: "24:00"}, {StartTime: "00:00", EndTime: "07:00"}},
		Location: "Australia/Sydney"}}
	assertUntil(t, ivs, time.Date(2026, 11, 19, 23, 30, 0, 0, sydney), time.Date(2026, 11, 20, 7, 0, 0, 0, sydney))
	assertUntil(t, ivs, time.Date(2026, 11, 20, 6, 59, 30, 0, sydney), time.Date(2026, 11, 20, 7, 0, 0, 0, sydney))
	assertUntil(t, ivs, time.Date(2026, 11, 19, 22, 0, 0, 0, sydney), time.Date(2026, 11, 20, 7, 0, 0, 0, sydney))
	assertNotQuiet(t, ivs, time.Date(2026, 11, 20, 7, 0, 0, 0, sydney)) // the end is excluded
	assertNotQuiet(t, ivs, time.Date(2026, 11, 19, 21, 59, 0, 0, sydney))
	assertNotQuiet(t, nil, time.Date(2026, 11, 19, 23, 30, 0, 0, sydney))
}

func TestQuietUntil_WeekdaysAndDaysOfMonth(t *testing.T) {
	weekend := []notify.TimeInterval{{Weekdays: []string{"saturday:sunday"}}}
	// 21 Nov 2026 is a Saturday.
	assertUntil(t, weekend, time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC), time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC))
	assertUntil(t, weekend, time.Date(2026, 11, 22, 23, 59, 0, 0, time.UTC), time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC))
	assertNotQuiet(t, weekend, time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC))
	assertNotQuiet(t, weekend, time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC))

	workHours := []notify.TimeInterval{{Weekdays: []string{"Monday:Friday"}, Times: []notify.TimeRange{{StartTime: "09:00", EndTime: "17:00"}}}}
	assertUntil(t, workHours, time.Date(2026, 11, 20, 16, 0, 0, 0, time.UTC), time.Date(2026, 11, 20, 17, 0, 0, 0, time.UTC))
	assertNotQuiet(t, workHours, time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC))

	// Weekday numbers run from 0 (Sunday) to 6 (Saturday), as in cron.
	numbered := []notify.TimeInterval{{Weekdays: []string{"1:5"}, Times: []notify.TimeRange{{StartTime: "09:00", EndTime: "17:00"}}}}
	assertUntil(t, numbered, time.Date(2026, 11, 20, 16, 0, 0, 0, time.UTC), time.Date(2026, 11, 20, 17, 0, 0, 0, time.UTC))
	assertNotQuiet(t, numbered, time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC))
	weekendNumbers := []notify.TimeInterval{{Weekdays: []string{"6:0"}}}
	assertUntil(t, weekendNumbers, time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC), time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC))
	assertNotQuiet(t, weekendNumbers, time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC))

	lastDay := []notify.TimeInterval{{DaysOfMonth: []string{"-1"}}}
	assertUntil(t, lastDay, time.Date(2026, 11, 30, 12, 0, 0, 0, time.UTC), time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
	assertNotQuiet(t, lastDay, time.Date(2026, 11, 29, 12, 0, 0, 0, time.UTC))
	assertUntil(t, lastDay, time.Date(2028, 2, 29, 12, 0, 0, 0, time.UTC), time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC))
	assertNotQuiet(t, lastDay, time.Date(2028, 2, 28, 12, 0, 0, 0, time.UTC))

	december := []notify.TimeInterval{{Months: []string{"december"}, Years: []string{"2026:2027"}, DaysOfMonth: []string{"24:26"}}}
	assertUntil(t, december, time.Date(2026, 12, 25, 8, 0, 0, 0, time.UTC), time.Date(2026, 12, 27, 0, 0, 0, 0, time.UTC))
	assertNotQuiet(t, december, time.Date(2028, 12, 25, 8, 0, 0, 0, time.UTC))

	always := []notify.TimeInterval{{}}
	start := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	assertUntil(t, always, start, start.Add(8*24*time.Hour)) // bounded at 8 days
}

func TestTimeInterval_ValidateRejectsBadInput(t *testing.T) {
	for name, ti := range map[string]notify.TimeInterval{
		"hour 25":        {Times: []notify.TimeRange{{StartTime: "25:00", EndTime: "26:00"}}},
		"24:00 as start": {Times: []notify.TimeRange{{StartTime: "24:00", EndTime: "24:00"}}},
		"one digit":      {Times: []notify.TimeRange{{StartTime: "9:00", EndTime: "17:00"}}},
		"backwards":      {Times: []notify.TimeRange{{StartTime: "17:00", EndTime: "09:00"}}},
		"bad weekday":    {Weekdays: []string{"monday:funday"}},
		"weekday 7":      {Weekdays: []string{"7"}},
		"weekday -1":     {Weekdays: []string{"-1"}},
		"day zero":       {DaysOfMonth: []string{"0"}},
		"day 32":         {DaysOfMonth: []string{"32"}},
		"month 13":       {Months: []string{"13"}},
		"months reverse": {Months: []string{"june:march"}},
		"bad location":   {Location: "Mars/Base"},
	} {
		assert.Error(t, ti.Validate(), name)
	}
	ok := notify.TimeInterval{Times: []notify.TimeRange{{StartTime: "22:00", EndTime: "24:00"}}, Weekdays: []string{"saturday:sunday", "wednesday", "1:5", "0"},
		DaysOfMonth: []string{"1:7", "-3:-1"}, Months: []string{"1:3", "december"}, Years: []string{"2026"}, Location: "Australia/Sydney"}
	assert.NoError(t, ok.Validate())
}
