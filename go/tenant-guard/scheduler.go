// Package tenant implements N4 tenant-guard — multi-tenant GPU scheduling.
//
// In production this runs as a Kubernetes operator (the ModelFleet / GPUQuota CRD controller
// is task 03). This package implements the **scheduling logic** itself — which is testable
// without a K8s cluster — using NVIDIA MIG (hardware partitioning) and MPS (software
// partitioning). The operator wrapper calls into this package.
//
// Per RFC N4: enforces per-tenant GPU quotas with per-tenant attestation (every allocation
// requires a valid AAE from I1 agent-identity).
package tenant

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// IsolationMode is how a GPU is partitioned for a tenant.
type IsolationMode string

const (
	// IsolationMIG uses NVIDIA MIG hardware partitioning (H100/H200). Strongest isolation.
	IsolationMIG IsolationMode = "mig"
	// IsolationMPS uses NVIDIA MPS software partitioning. Weaker isolation; more flexible.
	IsolationMPS IsolationMode = "mps"
	// IsolationNone runs tenants time-sliced on the same GPU (dev only).
	IsolationNone IsolationMode = "none"
)

// Errors returned by the scheduler.
var (
	// ErrQuotaExceeded is returned when a tenant's GPU quota is exhausted.
	ErrQuotaExceeded = errors.New("tenant-guard: quota exceeded")
	// ErrUntrustedIdentity is returned when an allocation is requested without a valid AAE.
	ErrUntrustedIdentity = errors.New("tenant-guard: untrusted identity (no valid AAE)")
	// ErrNoGPUs is returned when no GPUs are available.
	ErrNoGPUs = errors.New("tenant-guard: no GPUs available")
	// ErrUnknownTenant is returned when a tenant is not registered.
	ErrUnknownTenant = errors.New("tenant-guard: unknown tenant")
)

// TenantQuota is a tenant's GPU quota (per RFC N4 GPUQuota CRD).
type TenantQuota struct {
	TenantID       string        `json:"tenant_id"`
	MaxGPUs        int           `json:"max_gpus"`
	PreferredMode  IsolationMode `json:"preferred_mode"`
	// Per-tenant attestation: the AAE (P1) the tenant's agents must present.
	// An empty TrustedAAEHash disables attestation enforcement (CI only).
	TrustedAAEHash string `json:"trusted_aae_hash,omitempty"`
}

// Allocation is a GPU allocation for a tenant.
type Allocation struct {
	TenantID    string        `json:"tenant_id"`
	GPUID       string        `json:"gpu_id"`
	GPUModel    string        `json:"gpu_model"`
	Mode        IsolationMode `json:"mode"`
	Slice       string        `json:"slice,omitempty"` // MIG slice id (e.g. "1g.10gb") or MPS id
	AAEValidated bool         `json:"aae_validated"`
}

// GPU is a physical GPU that can be partitioned.
type GPU struct {
	ID         string
	Model      string // "H100", "H200", "B100"
	TotalMemoryGB int
	SupportsMIG bool
	SupportsMPS bool
	// Already-allocated slices (slice-id → tenant).
	migSlices map[string]string
	mpsClients map[string]string
	mu        sync.Mutex
}

// NewGPU constructs a new GPU with the given attributes and empty allocation.
func NewGPU(id, model string, memGB int, mig, mps bool) *GPU {
	return &GPU{
		ID:          id,
		Model:       model,
		TotalMemoryGB: memGB,
		SupportsMIG: mig,
		SupportsMPS: mps,
		migSlices:   map[string]string{},
		mpsClients:  map[string]string{},
	}
}

// CanAllocate reports whether this GPU can accept another tenant under `mode`.
func (g *GPU) CanAllocate(mode IsolationMode) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch mode {
	case IsolationMIG:
		return g.SupportsMIG && len(g.migSlices) < 7 // H100 supports up to 7 MIG slices
	case IsolationMPS:
		return g.SupportsMPS && len(g.mpsClients) < 48 // MPS supports many clients
	case IsolationNone:
		return true
	}
	return false
}

// Allocate assigns a slice to a tenant.
func (g *GPU) Allocate(tenantID string, mode IsolationMode) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch mode {
	case IsolationMIG:
		if !g.SupportsMIG || len(g.migSlices) >= 7 {
			return "", ErrQuotaExceeded
		}
		// Simple slice sizing: 1/7 of memory per slice.
		sliceID := fmt.Sprintf("%s-mig-%d", g.ID, len(g.migSlices))
		g.migSlices[sliceID] = tenantID
		return sliceID, nil
	case IsolationMPS:
		if !g.SupportsMPS {
			return "", ErrQuotaExceeded
		}
		sliceID := fmt.Sprintf("%s-mps-%d", g.ID, len(g.mpsClients))
		g.mpsClients[sliceID] = tenantID
		return sliceID, nil
	case IsolationNone:
		return g.ID, nil
	}
	return "", fmt.Errorf("tenant-guard: unknown isolation mode %q", mode)
}

// AllocatedTenants returns the tenants currently using this GPU.
func (g *GPU) AllocatedTenants() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	seen := map[string]struct{}{}
	for _, t := range g.migSlices {
		seen[t] = struct{}{}
	}
	for _, t := range g.mpsClients {
		seen[t] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Scheduler is the multi-tenant GPU scheduler.
type Scheduler struct {
	mu       sync.Mutex
	gpus     []*GPU
	quotas   map[string]*TenantQuota
	usage    map[string]int // tenantID → current allocation count
}

// NewScheduler constructs a scheduler with the given GPUs and no quotas.
func NewScheduler(gpus ...*GPU) *Scheduler {
	return &Scheduler{
		gpus:   gpus,
		quotas: map[string]*TenantQuota{},
		usage:  map[string]int{},
	}
}

// RegisterQuota registers (or replaces) a tenant's quota.
func (s *Scheduler) RegisterQuota(q TenantQuota) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quotas[q.TenantID] = &q
}

// Allocate assigns a GPU slice to a tenant. The aaeHash is the SHA-256 of the AAE the
// tenant's agent presented; it must match the quota's TrustedAAEHash (or the quota must
// have an empty TrustedAAEHash for CI mode).
func (s *Scheduler) Allocate(tenantID, aaeHash string) (*Allocation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	quota, ok := s.quotas[tenantID]
	if !ok {
		return nil, ErrUnknownTenant
	}
	// Per-tenant attestation enforcement.
	aaeValidated := false
	if quota.TrustedAAEHash == "" {
		// CI mode — no attestation required.
		aaeValidated = true
	} else if aaeHash == quota.TrustedAAEHash {
		aaeValidated = true
	} else {
		return nil, ErrUntrustedIdentity
	}

	// Quota enforcement.
	if s.usage[tenantID] >= quota.MaxGPUs {
		return nil, ErrQuotaExceeded
	}

	// Find a GPU that supports the preferred mode.
	var picked *GPU
	for _, g := range s.gpus {
		if g.CanAllocate(quota.PreferredMode) {
			picked = g
			break
		}
	}
	if picked == nil {
		// Fall back to None mode if available.
		for _, g := range s.gpus {
			if g.CanAllocate(IsolationNone) {
				picked = g
				break
			}
		}
	}
	if picked == nil {
		return nil, ErrNoGPUs
	}

	mode := quota.PreferredMode
	if !picked.CanAllocate(mode) {
		mode = IsolationNone
	}
	slice, err := picked.Allocate(tenantID, mode)
	if err != nil {
		return nil, err
	}
	s.usage[tenantID]++

	return &Allocation{
		TenantID:    tenantID,
		GPUID:       picked.ID,
		GPUModel:    picked.Model,
		Mode:        mode,
		Slice:       slice,
		AAEValidated: aaeValidated,
	}, nil
}

// Release frees an allocation.
func (s *Scheduler) Release(tenantID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.gpus {
		g.mu.Lock()
		for slice, t := range g.migSlices {
			if t == tenantID {
				delete(g.migSlices, slice)
			}
		}
		for slice, t := range g.mpsClients {
			if t == tenantID {
				delete(g.mpsClients, slice)
			}
		}
		g.mu.Unlock()
	}
	if s.usage[tenantID] > 0 {
		s.usage[tenantID]--
	}
}

// Usage returns the current per-tenant allocation counts.
func (s *Scheduler) Usage() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for k, v := range s.usage {
		out[k] = v
	}
	return out
}
