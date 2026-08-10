// Package provider defines the AumOS Terraform provider.
// This is a stub — the real provider wraps the AumOS HTTP/JSON APIs.
package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ provider.Provider = &aumosProvider{}
)

// NewProvider is a factory for the AumOS Terraform provider.
func NewProvider() provider.Provider {
	return &aumosProvider{}
}

type aumosProvider struct{}

// Provider schema model.
type aumosProviderModel struct {
	Endpoint     types.String `tfsdk:"endpoint"`
	TrustDomain  types.String `tfsdk:"trust_domain"`
	APIToken     types.String `tfsdk:"api_token"`
}

func (p *aumosProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "aumos"
	resp.Version = "1.0.0"
}

func (p *aumosProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage AumOS resources (components, identities, attestations, compliance reports).",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Description: "URL of the AumOS control plane (e.g. http://localhost:8441)",
				Optional:    true,
			},
			"trust_domain": schema.StringAttribute{
				Description: "SPIFFE trust domain (default: warrantor.dev)",
				Optional:    true,
			},
			"api_token": schema.StringAttribute{
				Description: "API token for authentication",
				Optional:    true,
				Sensitive:   true,
			},
		},
	}
}

func (p *aumosProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config aumosProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// Store config for resources to use
	resp.DataSourceData = &config
	resp.ResourceData = &config
}

func (p *aumosProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewComponentResource,
		NewIdentityResource,
	}
}

func (p *aumosProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewComplianceReportDataSource,
	}
}

// --- Resources ---

type componentResource struct{}

func NewComponentResource() resource.Resource { return &componentResource{} }

func (r *componentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_component"
}

func (r *componentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Install and verify an AumOS component.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{Required: true, Description: "Component name (e.g. trust-core)"},
			"version": schema.StringAttribute{Optional: true, Description: "Component version"},
			"installed": schema.BoolAttribute{Computed: true, Description: "Whether the component is installed"},
		},
	}
}

func (r *componentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Stub: in production, calls `defstack install <name>`
	var data struct {
		Name     types.String `tfsdk:"name"`
		Version  types.String `tfsdk:"version"`
		Installed types.Bool  `tfsdk:"installed"`
	}
	diags := req.Plan.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() { return }
	data.Installed = types.BoolValue(true)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *componentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {}
func (r *componentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {}
func (r *componentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {}

type identityResource struct{}

func NewIdentityResource() resource.Resource { return &identityResource{} }

func (r *identityResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_identity"
}

func (r *identityResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Issue an AumOS agent identity (SVID).",
		Attributes: map[string]schema.Attribute{
			"subject": schema.StringAttribute{Required: true, Description: "Agent SPIFFE SVID subject"},
			"svid": schema.StringAttribute{Computed: true, Description: "Issued SVID token"},
		},
	}
}

func (r *identityResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data struct {
		Subject types.String `tfsdk:"subject"`
		SVID    types.String `tfsdk:"svid"`
	}
	diags := req.Plan.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() { return }
	data.SVID = types.StringValue(fmt.Sprintf("svid-stub-for-%s", data.Subject.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *identityResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {}
func (r *identityResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {}
func (r *identityResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {}

// --- Data Sources ---

type complianceReportDataSource struct{}

func NewComplianceReportDataSource() datasource.DataSource { return &complianceReportDataSource{} }

func (d *complianceReportDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_compliance_report"
}

func (d *complianceReportDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Generate an AumOS compliance report.",
		Attributes: map[string]schema.Attribute{
			"model": schema.StringAttribute{Optional: true, Description: "Model to scope the report"},
			"report": schema.StringAttribute{Computed: true, Description: "JSON compliance report"},
		},
	}
}

func (d *complianceReportDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data struct {
		Model  types.String `tfsdk:"model"`
		Report types.String `tfsdk:"report"`
	}
	diags := req.Config.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() { return }
	data.Report = types.StringValue(`{"status":"stub","frameworks":10}`)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
