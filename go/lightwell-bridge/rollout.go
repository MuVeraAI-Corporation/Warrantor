package lightwellbridge

import (
	"errors"
	"fmt"
	"time"
)

// RolloutStrategy enumerates the rollout strategies.
type RolloutStrategy string

const (
	// StrategyImmediate rolls out to 100% immediately.
	StrategyImmediate RolloutStrategy = "immediate"
	// StrategyCanary rolls out in waves (default 1%, 10%, 50%, 100%).
	StrategyCanary RolloutStrategy = "canary"
	// StrategyStaged rolls out in N equal waves.
	StrategyStaged RolloutStrategy = "staged"
)

// AllStrategies returns every RolloutStrategy in canonical order.
func AllStrategies() []RolloutStrategy {
	return []RolloutStrategy{StrategyImmediate, StrategyCanary, StrategyStaged}
}

// RolloutPolicy describes how a bundle is rolled out.
type RolloutPolicy struct {
	// Strategy is the rollout strategy.
	Strategy RolloutStrategy
	// Waves is the wave percentages (0..100). For canary the default is
	// [1, 10, 50, 100]; for staged it is [100/N] * N.
	Waves []int
	// SoakSeconds is the minimum dwell time per wave (default 300).
	SoakSeconds int
	// MaxFailures is the abort threshold across the rollout (default 1).
	MaxFailures int
}

// Validate returns nil iff the policy is well-formed.
func (p RolloutPolicy) Validate() error {
	switch p.Strategy {
	case StrategyImmediate, StrategyCanary, StrategyStaged:
	default:
		return fmt.Errorf("unknown strategy %q", p.Strategy)
	}
	if p.SoakSeconds < 0 {
		return errors.New("soak_seconds must be >= 0")
	}
	if p.MaxFailures < 0 {
		return errors.New("max_failures must be >= 0")
	}
	for i, w := range p.Waves {
		if w < 0 || w > 100 {
			return fmt.Errorf("wave[%d]=%d out of range [0,100]", i, w)
		}
	}
	// waves must be strictly increasing and end at 100 for non-immediate
	if p.Strategy != StrategyImmediate && len(p.Waves) > 0 {
		last := -1
		for i, w := range p.Waves {
			if w <= last {
				return fmt.Errorf("wave[%d]=%d not strictly increasing", i, w)
			}
			last = w
		}
		if last != 100 {
			return fmt.Errorf("waves must end at 100, got %d", last)
		}
	}
	return nil
}

// DefaultPolicy returns a sensible default policy for a strategy.
func DefaultPolicy(strategy RolloutStrategy) RolloutPolicy {
	switch strategy {
	case StrategyImmediate:
		return RolloutPolicy{Strategy: strategy, Waves: []int{100}, SoakSeconds: 0, MaxFailures: 0}
	case StrategyCanary:
		return RolloutPolicy{Strategy: strategy, Waves: []int{1, 10, 50, 100}, SoakSeconds: 300, MaxFailures: 1}
	case StrategyStaged:
		return RolloutPolicy{Strategy: strategy, Waves: []int{25, 50, 100}, SoakSeconds: 600, MaxFailures: 1}
	}
	return RolloutPolicy{Strategy: strategy}
}

// Soak returns the dwell time for the policy.
func (p RolloutPolicy) Soak() time.Duration {
	return time.Duration(p.SoakSeconds) * time.Second
}
