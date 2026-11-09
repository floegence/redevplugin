// Package schedule owns durable host-neutral schedules and claim receipts.
// A claim is an intent to dispatch, never execution or resource authorization.
package schedule

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalid  = errors.New("invalid schedule")
	ErrConflict = errors.New("schedule revision conflict")
	ErrNotFound = errors.New("schedule not found")
	ErrLocked   = errors.New("schedule store is already open")
)

type Cadence struct {
	Kind       string `json:"kind"`
	IntervalMS int64  `json:"interval_ms,omitempty"`
	Timezone   string `json:"timezone,omitempty"`
	Hour       int    `json:"hour,omitempty"`
	Minute     int    `json:"minute,omitempty"`
}

func (c Cadence) Validate() error {
	switch c.Kind {
	case "interval", "completion":
		if c.IntervalMS < 1000 || c.IntervalMS > int64(365*24*time.Hour/time.Millisecond) || c.Timezone != "" || c.Hour != 0 || c.Minute != 0 {
			return ErrInvalid
		}
	case "daily":
		if c.IntervalMS != 0 || c.Hour < 0 || c.Hour > 23 || c.Minute < 0 || c.Minute > 59 || strings.TrimSpace(c.Timezone) == "" {
			return ErrInvalid
		}
		if _, err := time.LoadLocation(c.Timezone); err != nil {
			return fmt.Errorf("%w: timezone", ErrInvalid)
		}
	default:
		return ErrInvalid
	}
	return nil
}

// Next returns the next strict occurrence. Daily gaps use the first valid wall
// minute after the requested time; a repeated wall time runs only once per date.
func (c Cadence) Next(after time.Time) (time.Time, error) {
	if err := c.Validate(); err != nil {
		return time.Time{}, err
	}
	if after.IsZero() {
		return time.Time{}, ErrInvalid
	}
	if c.Kind != "daily" {
		return after.Add(time.Duration(c.IntervalMS) * time.Millisecond), nil
	}
	loc, _ := time.LoadLocation(c.Timezone)
	local := after.In(loc)
	for d := 0; d < 4; d++ {
		date := time.Date(local.Year(), local.Month(), local.Day()+d, 12, 0, 0, 0, loc)
		occurrence, ok := dailyOccurrence(date, c.Hour, c.Minute, loc)
		if ok && occurrence.After(after) {
			return occurrence, nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: daily occurrence unavailable", ErrInvalid)
}

func dailyOccurrence(date time.Time, hour, minute int, loc *time.Location) (time.Time, bool) {
	// Scan absolute minutes in the requested civil date. This handles gaps and
	// folds without relying on time.Date's unspecified choice for ambiguous times.
	start := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, time.UTC).Add(-24 * time.Hour)
	for i := 0; i < 72*60; i++ {
		at := start.Add(time.Duration(i) * time.Minute)
		wall := at.In(loc)
		if wall.Year() == date.Year() && wall.Month() == date.Month() && wall.Day() == date.Day() && wall.Hour()*60+wall.Minute() >= hour*60+minute {
			return at, true
		}
	}
	return time.Time{}, false
}

// Due returns the latest occurrence at or before now and the next occurrence.
func (c Cadence) Due(next, now time.Time) (latest, future time.Time, err error) {
	if now.Before(next) {
		return time.Time{}, next, nil
	}
	if err = c.Validate(); err != nil {
		return
	}
	if c.Kind == "completion" {
		return next, time.Time{}, nil
	}
	if c.Kind == "interval" {
		step := time.Duration(c.IntervalMS) * time.Millisecond
		latest = next.Add((now.Sub(next) / step) * step)
		return latest, latest.Add(step), nil
	}
	loc, _ := time.LoadLocation(c.Timezone)
	local := now.In(loc)
	for d := 0; d < 4; d++ {
		date := time.Date(local.Year(), local.Month(), local.Day()-d, 12, 0, 0, 0, loc)
		at, ok := dailyOccurrence(date, c.Hour, c.Minute, loc)
		if ok && !at.After(now) && !at.Before(next) {
			latest = at
			break
		}
	}
	if latest.IsZero() {
		latest = next
	}
	future, err = c.Next(latest)
	return
}
