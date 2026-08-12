// terraform-provider-warrantor — manage Warrantor resources as Infrastructure-as-Code.
//
// Resources:
//   - warrantor_component: install/verify an Warrantor component
//   - warrantor_identity: issue an agent identity (SVID)
//   - warrantor_attestation: request and verify a GPU attestation
//   - warrantor_compliance_report: generate a compliance report
//
// This is a stub provider using the Terraform Plugin Framework.
// The real provider wraps the Warrantor HTTP/JSON APIs.
package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

// Provider schema constants
const (
	providerVersion = "1.0.0"
)

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "Start provider in debug mode")
	flag.Parse()

	err := providerserver.Serve(context.Background(), NewProvider, providerserver.ServeOpts{
		Address:         "registry.terraform.io/MuVeraAI/warrantor",
		Debug:           debug,
		ProtocolVersion: 6,
	})
	if err != nil {
		fmt.Printf("Error starting provider: %v\n", err)
	}
}
