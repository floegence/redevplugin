package performanceevidence

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

type Metric struct {
	Name       string  `json:"name"`
	Unit       string  `json:"unit"`
	Observed   float64 `json:"observed"`
	Limit      float64 `json:"limit"`
	Comparator string  `json:"comparator"`
}

type Scenario struct {
	ID          string   `json:"id"`
	Gate        string   `json:"gate"`
	Status      string   `json:"status"`
	SampleCount int      `json:"sample_count"`
	Metrics     []Metric `json:"metrics"`
}

func Record(path string, scenario Scenario) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if strings.TrimSpace(scenario.ID) == "" || scenario.SampleCount < 1 || len(scenario.Metrics) == 0 {
		return errors.New("performance scenario is incomplete")
	}
	scenario.Status = "pass"
	raw, err := json.Marshal(scenario)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func Gate() string {
	gate := strings.TrimSpace(os.Getenv("REDEVPLUGIN_PERFORMANCE_GATE"))
	if gate == "" {
		return "full"
	}
	return gate
}

func EnforceThresholds() bool {
	gate := Gate()
	return gate == "full" || gate == "release"
}

func P95(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	index := (len(ordered)*95 + 99) / 100
	return ordered[index-1]
}

func RelativeBasisPoints(observed, baseline float64) (float64, error) {
	if !isFiniteNonNegative(observed) || !isFiniteNonNegative(baseline) || baseline == 0 {
		return 0, errors.New("performance ratio requires finite non-negative values and a positive baseline")
	}
	return observed / baseline * 10_000, nil
}

func isFiniteNonNegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}
