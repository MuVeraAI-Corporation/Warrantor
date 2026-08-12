// Package cloud implements X11 defstack-cloud — the managed SaaS control plane for Warrantor Cloud.
//
// defstack-cloud is the multi-tenant control plane that fronts the sovereign-stack components
// (X10) for customers who want a hosted experience. This package implements the control-plane
// logic itself — tenant lifecycle, per-plan GPU quotas, and GPU allocation — which is testable
// without a Kubernetes scheduler. The CRD-controller / API-server wrapper (task 03) calls into
// this package.
//
// Per RFC X11, each plan maps to a fixed GPU quota and a set of defaults:
//
//	free             0 GPUs, attestation required, no SLA
//	team             1 GPU,  attestation required, standard SLA
//	enterprise       10 GPUs, attestation required, premium SLA
//	mission_critical 100 GPUs, attestation required, mission-critical SLA
package cloud

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Plan is a defstack-cloud subscription tier.
type Plan string

const (
	// PlanFree is the no-cost tier: no GPUs, attestation required, best-effort.
	PlanFree Plan = "free"
	// PlanTeam is the team tier: 1 GPU, attestation required, standard SLA.
	PlanTeam Plan = "team"
	// PlanEnterprise is the enterprise tier: 10 GPUs, attestation required, premium SLA.
	PlanEnterprise Plan = "enterprise"
	// PlanMissionCritical is the top tier: 100 GPUs, attestation required, mission-critical SLA.
	PlanMissionCritical Plan = "mission_critical"
)

// AllPlans lists every supported plan, lowest to highest tier.
func AllPlans() []Plan {
	return []Plan{PlanFree, PlanTeam, PlanEnterprise, PlanMissionCritical}
}

// SLATier names the support SLA attached to a plan.
type SLATier string

const (
	SLANone            SLATier = "none"
	SLAStandard        SLATier = "standard"
	SLAPremium         SLATier = "premium"
	SLAMissionCritical SLATier = "mission_critical"
)

// Errors returned by this package.
var (
	// ErrUnknownPlan is returned when a plan is not recognized.
	ErrUnknownPlan = errors.New("cloud: unknown plan")
	// ErrTenantExists is returned when provisioning a tenant id that already exists.
	ErrTenantExists = errors.New("cloud: tenant already exists")
	// ErrUnknownTenant is returned when an operation references an unknown tenant.
	ErrUnknownTenant = errors.New("cloud: unknown tenant")
	// ErrQuotaExceeded is returned when a tenant's GPU quota is exhausted.
	ErrQuotaExceeded = errors.New("cloud: gpu quota exceeded")
	// ErrGPUsExhausted is returned when the control plane's GPU pool is empty.
	ErrGPUsExhausted = errors.New("cloud: gpu pool exhausted")
)

// PlanDefaults are the defaults attached to a tenant at provisioning time.
type PlanDefaults struct {
	// Plan these defaults belong to.
	Plan Plan `json:"plan"`
	// GPUQuota is the maximum number of GPUs the tenant may hold simultaneously.
	GPUQuota int `json:"gpu_quota"`
	// AttestationRequired is true when the tenant's agents must present a valid AAE (P1)
	// for every allocation. True for every plan in v1.0.
	AttestationRequired bool `json:"attestation_required"`
	// SLATier is the support SLA attached to the plan.
	SLATier SLATier `json:"sla_tier"`
}

// PlanDefaultsMap is the per-plan default map. Free plans cannot allocate GPUs; the higher
// tiers get progressively larger quotas and better SLAs.
var PlanDefaultsMap = map[Plan]PlanDefaults{
	PlanFree:            {Plan: PlanFree, GPUQuota: 0, AttestationRequired: true, SLATier: SLANone},
	PlanTeam:            {Plan: PlanTeam, GPUQuota: 1, AttestationRequired: true, SLATier: SLAStandard},
	PlanEnterprise:      {Plan: PlanEnterprise, GPUQuota: 10, AttestationRequired: true, SLATier: SLAPremium},
	PlanMissionCritical: {Plan: PlanMissionCritical, GPUQuota: 100, AttestationRequired: true, SLATier: SLAMissionCritical},
}

// DefaultsFor returns the plan defaults for a plan, or ErrUnknownPlan.
func DefaultsFor(plan Plan) (PlanDefaults, error) {
	d, ok := PlanDefaultsMap[plan]
	if !ok {
		return PlanDefaults{}, fmt.Errorf("%w: %q", ErrUnknownPlan, plan)
	}
	return d, nil
}

// Tenant is a defstack-cloud customer tenant.
type Tenant struct {
	ID        string    `json:"id"`
	Plan      Plan      `json:"plan"`
	GPUQuota  int       `json:"gpu_quota"`
	CreatedAt time.Time `json:"created_at"`
	// AttestationRequired mirrors the plan default at provisioning time.
	AttestationRequired bool `json:"attestation_required"`
	// SLATier mirrors the plan default at provisioning time.
	SLATier SLATier `json:"sla_tier"`
}

// Allocation is a GPU assigned to a tenant.
type Allocation struct {
	TenantID string    `json:"tenant_id"`
	GPUID    string    `json:"gpu_id"`
	Plan     Plan      `json:"plan"`
	Granted  time.Time `json:"granted"`
}

// ControlPlane manages tenants and the shared GPU pool.
type ControlPlane struct {
	mu      sync.Mutex
	tenants map[string]*Tenant
	// tenantAllocations: tenantID -> set of GPU ids held by that tenant.
	tenantAllocations map[string]map[string]struct{}
	// gpuOwner: GPU id -> tenant id currently holding it.
	gpuOwner map[string]string
	// The id pool of GPUs available to the control plane.
	gpuPool []string
	// nextGPU indexes the first un-assigned GPU in gpuPool.
	nextGPU int
	// clock is injected for deterministic CreatedAt/Granted in tests.
	clock func() time.Time
	// allocCount is a global counter for generating allocation sequence numbers.
	allocCount atomic.Int64
}

// ControlPlaneConfig configures a new ControlPlane.
type ControlPlaneConfig struct {
	// GPU ids available to the control plane (e.g. ["gpu-0","gpu-1",...]).
	GPUs []string
	// Optional clock; defaults to time.Now.
	Now func() time.Time
}

// NewControlPlane constructs a control plane with the given GPU pool.
func NewControlPlane(cfg ControlPlaneConfig) *ControlPlane {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &ControlPlane{
		tenants:           map[string]*Tenant{},
		tenantAllocations: map[string]map[string]struct{}{},
		gpuOwner:          map[string]string{},
		gpuPool:           append([]string(nil), cfg.GPUs...),
		clock:             now,
	}
}

// ProvisionTenant creates a tenant with per-plan defaults. Returns ErrTenantExists if the id
// is already taken, or ErrUnknownPlan if the plan is not recognized.
func (cp *ControlPlane) ProvisionTenant(tenantID string, plan Plan) (*Tenant, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if _, ok := cp.tenants[tenantID]; ok {
		return nil, fmt.Errorf("%w: %q", ErrTenantExists, tenantID)
	}
	defaults, err := DefaultsFor(plan)
	if err != nil {
		return nil, err
	}
	t := &Tenant{
		ID:                  tenantID,
		Plan:                plan,
		GPUQuota:            defaults.GPUQuota,
		AttestationRequired: defaults.AttestationRequired,
		SLATier:             defaults.SLATier,
		CreatedAt:           cp.clock(),
	}
	cp.tenants[tenantID] = t
	cp.tenantAllocations[tenantID] = map[string]struct{}{}
	return t, nil
}

// DeprovisionTenant removes a tenant and frees all of its GPU allocations. Returns
// ErrUnknownTenant if the tenant does not exist.
func (cp *ControlPlane) DeprovisionTenant(tenantID string) error {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if _, ok := cp.tenants[tenantID]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknownTenant, tenantID)
	}
	held := cp.tenantAllocations[tenantID]
	for gpu := range held {
		owner, ok := cp.gpuOwner[gpu]
		if ok && owner == tenantID {
			delete(cp.gpuOwner, gpu)
			// Return the GPU to the back of the free list.
			cp.gpuPool = append(cp.gpuPool, gpu)
		}
	}
	delete(cp.tenantAllocations, tenantID)
	delete(cp.tenants, tenantID)
	return nil
}

// GetTenant returns a copy of a tenant record, or ErrUnknownTenant.
func (cp *ControlPlane) GetTenant(tenantID string) (*Tenant, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	t, ok := cp.tenants[tenantID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTenant, tenantID)
	}
	out := *t
	return &out, nil
}

// AllocateGPU assigns the next free GPU to a tenant, respecting the tenant's per-plan quota.
// Returns ErrUnknownTenant, ErrQuotaExceeded, or ErrGPUsExhausted as appropriate.
func (cp *ControlPlane) AllocateGPU(tenantID string) (*Allocation, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	t, ok := cp.tenants[tenantID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTenant, tenantID)
	}
	held := cp.tenantAllocations[tenantID]
	if len(held) >= t.GPUQuota {
		return nil, fmt.Errorf("%w: tenant %q has quota %d and holds %d",
			ErrQuotaExceeded, tenantID, t.GPUQuota, len(held))
	}
	gpu, ok := cp.nextFreeGPU()
	if !ok {
		return nil, ErrGPUsExhausted
	}
	cp.gpuOwner[gpu] = tenantID
	held[gpu] = struct{}{}
	return &Allocation{
		TenantID: tenantID,
		GPUID:    gpu,
		Plan:     t.Plan,
		Granted:  cp.clock(),
	}, nil
}

// ReleaseGPU frees a specific GPU back to the pool. No-op if the tenant does not own it.
func (cp *ControlPlane) ReleaseGPU(tenantID, gpuID string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	held, ok := cp.tenantAllocations[tenantID]
	if !ok {
		return
	}
	if _, owns := held[gpuID]; !owns {
		return
	}
	delete(held, gpuID)
	delete(cp.gpuOwner, gpuID)
	cp.gpuPool = append(cp.gpuPool, gpuID)
}

// TenantHeldGPUs returns the GPU ids a tenant currently holds.
func (cp *ControlPlane) TenantHeldGPUs(tenantID string) ([]string, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	held, ok := cp.tenantAllocations[tenantID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTenant, tenantID)
	}
	out := make([]string, 0, len(held))
	for g := range held {
		out = append(out, g)
	}
	return out, nil
}

// Allocated returns the GPU ids currently in use across all tenants.
func (cp *ControlPlane) Allocated() []string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	out := make([]string, 0, len(cp.gpuOwner))
	for g := range cp.gpuOwner {
		out = append(out, g)
	}
	return out
}

// TenantCount returns the number of provisioned tenants.
func (cp *ControlPlane) TenantCount() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return len(cp.tenants)
}

// nextFreeGPU pops the first available GPU from the free list. Caller must hold cp.mu.
// Freed GPUs are appended to the back of gpuPool, so this reclaims them in FIFO order.
func (cp *ControlPlane) nextFreeGPU() (string, bool) {
	for cp.nextGPU < len(cp.gpuPool) {
		gpu := cp.gpuPool[cp.nextGPU]
		cp.nextGPU++
		// Skip if it was re-owned by a tenant while in-flight (defensive; should not happen
		// under the mutex, but cheap to guard against).
		if _, taken := cp.gpuOwner[gpu]; taken {
			continue
		}
		return gpu, true
	}
	return "", false
}
