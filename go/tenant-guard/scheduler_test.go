package tenant

import (
	"errors"
	"testing"
)

func freshScheduler() *Scheduler {
	// Two H100s (MIG+MPS) + one A100 (MPS only).
	return NewScheduler(
		NewGPU("gpu-0", "H100", 80, true, true),
		NewGPU("gpu-1", "H100", 80, true, true),
		NewGPU("gpu-2", "A100", 40, false, true),
	)
}

func TestAllocateUnderQuota(t *testing.T) {
	s := freshScheduler()
	s.RegisterQuota(TenantQuota{TenantID: "t1", MaxGPUs: 2, PreferredMode: IsolationMIG})
	a, err := s.Allocate("t1", "")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if a.TenantID != "t1" || a.GPUID != "gpu-0" {
		t.Errorf("unexpected allocation: %+v", a)
	}
	if a.Mode != IsolationMIG {
		t.Errorf("expected MIG mode, got %s", a.Mode)
	}
}

func TestAllocateEnforcesQuota(t *testing.T) {
	s := freshScheduler()
	s.RegisterQuota(TenantQuota{TenantID: "t1", MaxGPUs: 1, PreferredMode: IsolationMIG})
	if _, err := s.Allocate("t1", ""); err != nil {
		t.Fatalf("first Allocate: %v", err)
	}
	_, err := s.Allocate("t1", "")
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("expected ErrQuotaExceeded, got %v", err)
	}
}

func TestAllocateRequiresTrustedAAE(t *testing.T) {
	s := freshScheduler()
	s.RegisterQuota(TenantQuota{
		TenantID:       "t1",
		MaxGPUs:        1,
		PreferredMode:  IsolationMIG,
		TrustedAAEHash: "sha256:expected",
	})
	_, err := s.Allocate("t1", "sha256:wrong")
	if !errors.Is(err, ErrUntrustedIdentity) {
		t.Errorf("expected ErrUntrustedIdentity, got %v", err)
	}
	// Correct hash → succeeds.
	a, err := s.Allocate("t1", "sha256:expected")
	if err != nil {
		t.Fatalf("Allocate with correct AAE: %v", err)
	}
	if !a.AAEValidated {
		t.Error("expected AAEValidated=true")
	}
}

func TestAllocateUnknownTenantFails(t *testing.T) {
	s := freshScheduler()
	_, err := s.Allocate("nobody", "")
	if !errors.Is(err, ErrUnknownTenant) {
		t.Errorf("expected ErrUnknownTenant, got %v", err)
	}
}

func TestAllocateFallsBackToMPSForNonMIGGPU(t *testing.T) {
	s := freshScheduler()
	s.RegisterQuota(TenantQuota{TenantID: "t1", MaxGPUs: 1, PreferredMode: IsolationMPS})
	a, err := s.Allocate("t1", "")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if a.Mode != IsolationMPS {
		t.Errorf("expected MPS, got %s", a.Mode)
	}
}

func TestReleaseDecrementsUsage(t *testing.T) {
	s := freshScheduler()
	s.RegisterQuota(TenantQuota{TenantID: "t1", MaxGPUs: 1, PreferredMode: IsolationMIG})
	if _, err := s.Allocate("t1", ""); err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if s.Usage()["t1"] != 1 {
		t.Errorf("usage after allocate = %d", s.Usage()["t1"])
	}
	s.Release("t1")
	if s.Usage()["t1"] != 0 {
		t.Errorf("usage after release = %d", s.Usage()["t1"])
	}
	// After release, can allocate again.
	if _, err := s.Allocate("t1", ""); err != nil {
		t.Errorf("re-allocate after release: %v", err)
	}
}

func TestGPUAllocationCount(t *testing.T) {
	s := freshScheduler()
	s.RegisterQuota(TenantQuota{TenantID: "t1", MaxGPUs: 3, PreferredMode: IsolationMIG})
	s.RegisterQuota(TenantQuota{TenantID: "t2", MaxGPUs: 3, PreferredMode: IsolationMIG})
	// Two tenants each get one MIG slice on gpu-0 and gpu-1.
	if _, err := s.Allocate("t1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Allocate("t2", ""); err != nil {
		t.Fatal(err)
	}
	// gpu-0 should now host both tenants.
	tenants := s.gpus[0].AllocatedTenants()
	if len(tenants) != 2 {
		t.Errorf("expected 2 tenants on gpu-0, got %v", tenants)
	}
}

func TestGPUCanAllocateRespectsMIGLimit(t *testing.T) {
	g := NewGPU("g", "H100", 80, true, true)
	for i := 0; i < 7; i++ {
		g.migSlices[string(rune('a'+i))] = "t"
	}
	if g.CanAllocate(IsolationMIG) {
		t.Error("GPU at 7 MIG slices should not be allocatable")
	}
	if !g.CanAllocate(IsolationMPS) {
		t.Error("GPU should still be allocatable for MPS")
	}
}

func TestNoGPUsError(t *testing.T) {
	s := NewScheduler() // empty
	s.RegisterQuota(TenantQuota{TenantID: "t1", MaxGPUs: 1, PreferredMode: IsolationMIG})
	_, err := s.Allocate("t1", "")
	if !errors.Is(err, ErrNoGPUs) {
		t.Errorf("expected ErrNoGPUs, got %v", err)
	}
}
