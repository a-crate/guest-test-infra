package wsfc

import (
	"fmt"
	"math/rand"

	"github.com/GoogleCloudPlatform/compute-daisy"
	"github.com/GoogleCloudPlatform/guest-test-infra/imagetest"
	"github.com/GoogleCloudPlatform/guest-test-infra/imagetest/utils"
	"google.golang.org/api/compute/v1"
)

var (
	// Name is the name of the test package. It must match the directory name.
	Name         = "wsfc"

	domain = "cloudimagetest.google.com"
	domainuser_without_domain = "TestUser"
	domainuser = domain+`\`+domainuser_without_domain

	wsfcVIP = "10.1.2.100"

	adBackend1IP4Addr = "10.1.2.10"
	adBackend2IP4Addr = "10.1.2.20"

	adControllerIP4Addr = "10.1.2.50"

	ad_setup_script=`# Use the existence of a file to determine whether this is first boot
# (pre-AD initialization) or second boot.
$addsforest = 'C:\adds_forest_install.txt'
$domain = 'cloudimagetest.google.com'

if (Test-Path $addsforest) {
  while (-not $ad_controller) {
    try {
     $ad_controller = Get-ADDomainController -Discover -Domain $domain -ErrorAction stop
     } catch {
       Write-Host $_
       Start-Sleep -second 10
     }
  }

  # Test can look for this string in serial output to know that the controller
  # is set up.  Must match string in active_directory_test.py.
  cmd /c 'echo Running as AD controller. > COM1:'
  netsh interface ip set address name=Ethernet static 10.1.2.50 255.255.255.0 10.1.2.1
  exit 0
}

Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment
'Running Install-ADDSForest.' | Set-Content $addsforest

net user Administrator '%s'

Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "WinThreshold" -DomainName "cloudimagetest.google.com" -DomainNetbiosName "CLOUDIMAGETEST" -ForestMode "WinThreshold" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -SafeModeAdministratorPassword (ConvertTo-SecureString -String '%s' -AsPlainText -Force) -Force:$true
`
)

// TestSetup sets up the test workflow.
func TestSetup(t *imagetest.TestWorkflow) error {
	passwd := utils.ValidWindowsPassword(14)
	lbnet, err := t.CreateNetwork("wsfc", false)
	if err != nil {
		return err
	}
	lbsubnet, err := lbnet.CreateSubnetwork("lb-backend-subnet", "10.1.2.0/24")
	if err != nil {
		return err
	}
	if err := lbnet.CreateFirewallRule("fw-allow-health-check", "all", nil, []string{"130.211.0.0/22", "35.191.0.0/16"}); err != nil {
		return err
	}
	if err := lbnet.CreateFirewallRule("fw-lb-access", "all", nil, []string{"10.1.2.0/24"}); err != nil {
		return err
	}

	mkvm := func(name, ip, test string) (*imagetest.TestVM, *daisy.Instance, error) {
		inst := &daisy.Instance{}
		vm, err := t.CreateTestVMMultipleDisks([]*compute.Disk{{Name: name}}, inst)
		if err != nil {
			return nil, nil, err
		}
		if err := vm.AddCustomNetwork(lbnet, lbsubnet); err != nil {
			return nil, nil, err
		}
		if err := vm.SetPrivateIP(lbnet, ip); err != nil {
			return nil, nil, err
		}
		vm.AddMetadata("admin-passwd", passwd)
		vm.RunTests(test)
		return vm, inst, nil
	}
	mkbackend := func(name, ip, test string) error {
		vm, inst, err := mkvm(name, ip, test)
		if err != nil {
			return err
		}
		inst.CanIpForward = true
		vm.AddMetadata("enable-wsfc", "true")
		vm.AddMetadata("use-static-ip", ip)
		vm.AddMetadata("sysprep-specialize-script-ps1", `Install-WindowsFeature -Name File-Services, Failover-Clustering -IncludeManagementTools`)
		return nil
	}
	mkclient := func(name, ip, test string) error {
		vm, inst, err := mkvm(name, ip, test)
		if err != nil {
			return err
		}
//		vm.AddMetadata("sysprep-specialize-script-ps1", `Add-WindowsFeature "RSAT-AD-Tools"`)
		vm.AddMetadata("windows-startup-script-ps1", fmt.Sprintf(ad_setup_script, passwd, passwd))
		inst.Scopes = append(inst.Scopes, "https://www.googleapis.com/auth/cloud-platform")
		return nil
	}

	if err := mkbackend("adbackend1", adBackend1IP4Addr, "TestBackend"); err != nil {
		return err
	}
	if err := mkbackend("adbackend2", adBackend2IP4Addr, "TestBackend"); err != nil {
		return err
	}
	if err := mkclient("adcontroller", adControllerIP4Addr, "TestClient"); err != nil {
		return err
	}
	return nil
}

func genPw(length int) string {
	const allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-!@#$%^&*+"

	str := make([]byte, length)
	for i := 0; i < length; i++ {
		str[i] = allowedChars[rand.Intn(len(allowedChars))]
	}

	return string(str)
}
