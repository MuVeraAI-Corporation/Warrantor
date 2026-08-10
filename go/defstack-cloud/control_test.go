package cloud

import (
	"errors"
	"testing"
	"time"
)

func freshPlane(gpus int) *ControlPlane {
	pool := make([]string, gpus)
	for i := range pool {
		pool[i] = "gpu-" + string(rune('0'+i))
	}
	t0 := time.Unix(1_700_000_000, 0)
	now := t0
	return NewControlPlane(ControlPlaneConfig{
		GPUs: pool,
		Now:  func() time.Time { return now },
	})
}

func TestPlanDefaults(t *testing.T) {
	cases := []struct {
		plan       Plan
		wantQuota  int
		wantSLA    SLATier
		wantAttest bool
	}{
		{PlanFree, 0, SLANone, true},
		{PlanTeam, 1, SLAStandard, true},
		{PlanEnterprise, 10, SLAPremium, true},
		{PlanMissionCritical, 100, SLAMissionCritical, true},
	}
	for _, tc := range cases {
		d, err := DefaultsFor(tc.plan)
		if err != nil {
			t.Fatalf("%s: %v", tc.plan, err)
		}
		if d.GPUQuota != tc.wantQuota {
			t.Errorf("%s: quota = %d, want %d", tc.plan, d.GPUQuota, tc.wantQuota)
		}
		if d.SLATier != tc.wantSLA {
			t.Errorf("%s: sla = %s, want %s", tc.plan, d.SLATier, tc.wantSLA)
		}
		if d.AttestationRequired != tc.wantAttest {
			t.Errorf("%s: attestation = %v, want %v", tc.plan, d.AttestationRequired, tc.wantAttest)
		}
	}
}

func TestDefaultsForUnknownPlan(t *testing.T) {
	if _, err := DefaultsFor(Plan("bogus")); !errors.Is(err, ErrUnknownPlan) {
		t.Errorf("expected ErrUnknownPlan, got %v", err)
	}
}

func TestProvisionTenant(t *testing.T) {
	cp := freshPlane(5)
	tt, err := cp.ProvisionTenant("acme", PlanEnterprise)
	if err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	if tt.ID != "acme" || tt.Plan != PlanEnterprise || tt.GPUQuota != 10 {
		t.Errorf("unexpected tenant: %+v", tt)
	}
	if tt.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if !tt.AttestationRequired || tt.SLATier != SLAPremium {
		t.Errorf("plan defaults not applied: %+v", tt)
	}
}

func TestProvisionDuplicateRejected(t *testing.T) {
	cp := freshPlane(5)
	if _, err := cp.ProvisionTenant("acme", PlanFree); err != nil {
		t.Fatal(err)
	}
	_, err := cp.ProvisionTenant("acme", PlanTeam)
	if !errors.Is(err, ErrTenantExists) {
		t.Errorf("expected ErrTenantExists, got %v", err)
	}
}

func TestProvisionUnknownPlanRejected(t *testing.T) {
	cp := freshPlane(5)
	_, err := cp.ProvisionTenant("acme", Plan("bogus"))
	if !errors.Is(err, ErrUnknownPlan) {
		t.Errorf("expected ErrUnknownPlan, got %v", err)
	}
}

func TestAllocateGPUWithinQuota(t *testing.T) {
	cp := freshPlane(5)
	if _, err := cp.ProvisionTenant("acme", PlanTeam); err != nil { // quota = 1
		t.Fatal(err)
	}
	a, err := cp.AllocateGPU("acme")
	if err != nil {
		t.Fatalf("AllocateGPU: %v", err)
	}
	if a.TenantID != "acme" || a.GPUID != "gpu-0" || a.Plan != PlanTeam {
		t.Errorf("unexpected allocation: %+v", a)
	}
	held, err := cp.TenantHeldGPUs("acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || held[0] != "gpu-0" {
		t.Errorf("expected to hold gpu-0, got %v", held)
	}
}

func TestAllocateGPUEnforcesQuota(t *testing.T) {
	cp := freshPlane(5)
	if _, err := cp.ProvisionTenant("acme", PlanTeam); err != nil { // quota = 1
		t.Fatal(err)
	}
	if _, err := cp.AllocateGPU("acme"); err != nil {
		t.Fatal(err)
	}
	_, err := cp.AllocateGPU("acme")
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("expected ErrQuotaExceeded, got %v", err)
	}
}

func TestFreePlanCannotAllocate(t *testing.T) {
	cp := freshPlane(5)
	if _, err := cp.ProvisionTenant("freebie", PlanFree); err != nil {
		t.Fatal(err)
	}
	_, err := cp.AllocateGPU("freebie")
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("free plan quota is 0; expected ErrQuotaExceeded, got %v", err)
	}
}

func TestAllocateGPUUnknownTenant(t *testing.T) {
	cp := freshPlane(5)
	_, err := cp.AllocateGPU("ghost")
	if !errors.Is(err, ErrUnknownTenant) {
		t.Errorf("expected ErrUnknownTenant, got %v", err)
	}
}

func TestAllocateGPURunsOut(t *testing.T) {
	cp := freshPlane(2)
	if _, err := cp.ProvisionTenant("a", PlanEnterprise); err != nil { // quota 10, but pool has 2
		t.Fatal(err)
	}
	if _, err := cp.AllocateGPU("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := cp.AllocateGPU("a"); err != nil {
		t.Fatal(err)
	}
	_, err := cp.AllocateGPU("a")
	if !errors.Is(err, ErrGPUsExhausted) {
		t.Errorf("expected ErrGPUsExhausted, got %v", err)
	}
}

func TestDeprovisionFreesAllocations(t *testing.T) {
	cp := freshPlane(5)
	if _, err := cp.ProvisionTenant("acme", PlanEnterprise); err != nil {
		t.Fatal(err)
	}
	if _, err := cp.AllocateGPU("acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := cp.AllocateGPU("acme"); err != nil {
		t.Fatal(err)
	}
	if len(cp.Allocated()) != 2 {
		t.Errorf("expected 2 allocated, got %v", cp.Allocated())
	}
	if err := cp.DeprovisionTenant("acme"); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	if len(cp.Allocated()) != 0 {
		t.Errorf("deprovision should free all GPUs, got %v", cp.Allocated())
	}
	// The freed GPUs should be re-allocatable to a new tenant.
	if _, err := cp.ProvisionTenant("newco", PlanTeam); err != nil {
		t.Fatal(err)
	}
	if _, err := cp.AllocateGPU("newco"); err != nil {
		t.Errorf("re-allocate after deprovision: %v", err)
	}
}

func TestDeprovisionUnknownTenant(t *testing.T) {
	cp := freshPlane(5)
	if err := cp.DeprovisionTenant("ghost"); !errors.Is(err, ErrUnknownTenant) {
		t.Errorf("expected ErrUnknownTenant, got %v", err)
	}
}

func TestDeprovisionRemovesTenant(t *testing.T) {
	cp := freshPlane(5)
	if _, err := cp.ProvisionTenant("acme", PlanFree); err != nil {
		t.Fatal(err)
	}
	if cp.TenantCount() != 1 {
		t.Errorf("expected 1 tenant, got %d", cp.TenantCount())
	}
	if err := cp.DeprovisionTenant("acme"); err != nil {
		t.Fatal(err)
	}
	if cp.TenantCount() != 0 {
		t.Errorf("expected 0 tenants after deprovision, got %d", cp.TenantCount())
	}
	if _, err := cp.GetTenant("acme"); !errors.Is(err, ErrUnknownTenant) {
		t.Errorf("GetTenant after deprovision should be ErrUnknownTenant, got %v", err)
	}
}

func TestReleaseGPU(t *testing.T) {
	cp := freshPlane(3)
	if _, err := cp.ProvisionTenant("acme", PlanEnterprise); err != nil {
		t.Fatal(err)
	}
	a, err := cp.AllocateGPU("acme")
	if err != nil {
		t.Fatal(err)
	}
	cp.ReleaseGPU("acme", a.GPUID)
	held, _ := cp.TenantHeldGPUs("acme")
	if len(held) != 0 {
		t.Errorf("expected 0 held after release, got %v", held)
	}
	// Releasing an unowned GPU is a no-op (no panic).
	cp.ReleaseGPU("acme", "gpu-9")
	cp.ReleaseGPU("ghost", "gpu-0")
}

func TestGetTenantReturnsCopy(t *testing.T) {
	cp := freshPlane(5)
	if _, err := cp.ProvisionTenant("acme", PlanTeam); err != nil {
		t.Fatal(err)
	}
	got, err := cp.GetTenant("acme")
	if err != nil {
		t.Fatal(err)
	}
	got.GPUQuota = 999 // mutate the returned copy
	again, _ := cp.GetTenant("acme")
	if again.GPUQuota != 1 {
		t.Errorf("internal state was mutated through GetTenant: %+v", again)
	}
}

func TestAllPlansSortedByTier(t *testing.T) {
	want := []Plan{PlanFree, PlanTeam, PlanEnterprise, PlanMissionCritical}
	got := AllPlans()
	if len(got) != len(want) {
		t.Fatalf("AllPlans = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("AllPlans[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestMissionCriticalCanTakeFullPool(t *testing.T) {
	// Pool of exactly 100 GPUs; mission_critical quota is 100.
	pool := make([]string, 100)
	for i := range pool {
		pool[i] = "gpu-" + string(rune('a'+(i%26))) + string(rune('0'+(i/26)))
	}
	cp := NewControlPlane(ControlPlaneConfig{GPUs: pool})
	if _, err := cp.ProvisionTenant("mil", PlanMissionCritical); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if _, err := cp.AllocateGPU("mil"); err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
	}
	// 101st allocation fails on quota (quota=100) — not on pool exhaustion since they coincide.
	if _, err := cp.AllocateGPU("mil"); !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("expected ErrQuotaExceeded at 101, got %v", err)
	}
}
