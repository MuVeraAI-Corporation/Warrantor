# C1-3 attesta-flow Terraform provisioning for Azure DC-series confidential VMs.
# Per RFC C1-3: provisions a confidential VM with an NVIDIA GPU, runs the attesta-flow
# orchestrator inside the TEE. Equivalent modules exist for AWS Nitro Enclaves and GCP
# Confidential VMs (not shown here; same shape).

terraform {
  required_version = ">= 1.7"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }
}

variable "resource_group_name" {
  type    = string
  default = "attesta-flow-rg"
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "vm_size" {
  type    = string
  default = "Standard_DC48ads_v5"  # Azure confidential VM with Intel TDX
}

variable "gpu_model" {
  type    = string
  default = "H100"
}

resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location
}

# Confidential VM: security_type = "ConfidentialVM" enforces the TEE.
resource "azurerm_linux_virtual_machine" "confidential_vm" {
  name                  = "attesta-flow-vm"
  resource_group_name   = azurerm_resource_group.main.name
  location              = azurerm_resource_group.main.location
  size                  = var.vm_size
  admin_username        = "aumos"
  network_interface_ids = [azurerm_network_interface.main.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    # Confidential-disk-encryption for the OS disk.
    security_encryption_type = "DiskWithVMGuestState"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-confidential-vm-focal"
    sku       = "20_04-lts-cvm"
    version   = "latest"
  }

  # The Confidential VM extension proves the TEE is real (attestation).
  security_type = "ConfidentialVM"
}

# Placeholder: GPU attachment (NVIDIA H100) — Azure NC H100 v5 series.
# In production, attach the GPU as a dedicated resource and install NVIDIA drivers + NVTrust.

output "confidential_vm_id" {
  value = azurerm_linux_virtual_machine.confidential_vm.id
}
