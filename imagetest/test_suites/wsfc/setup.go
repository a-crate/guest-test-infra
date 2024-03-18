package wsfc

import (
	"github.com/GoogleCloudPlatform/compute-daisy"
	"github.com/GoogleCloudPlatform/guest-test-infra/imagetest"
	"google.golang.org/api/compute/v1"
)

var (
	// Name is the name of the test package. It must match the directory name.
	Name         = "wsfc"
	wsfcVIP = "10.1.2.100"

	adBackend1IP4Addr = "10.1.2.10"
	adBackend2IP4Addr = "10.1.2.20"

	adControllerIP4Addr = "10.1.2.50"
)

// TestSetup sets up the test workflow.
func TestSetup(t *imagetest.TestWorkflow) error {
	lbnet, err := t.CreateNetwork("wsfc", false)
	if err != nil {
		return err
	}
	lbsubnet, err := lbnet.CreateSubnetwork("lb-backend-subnet", "10.1.2.0/24")
	if err != nil {
		return err
	}
	if err := lbnet.CreateFirewallRule("fw-allow-health-check", "tcp", nil, []string{"130.211.0.0/22", "35.191.0.0/16"}); err != nil {
		return err
	}
	if err := lbnet.CreateFirewallRule("fw-lb-access", "tcp", nil, []string{"10.1.2.0/24"}); err != nil {
		return err
	}

	mkvm := func(name, ip, test string) (*daisy.Instance, error) {
		inst := &daisy.Instance{}
		vm, err := t.CreateTestVMMultipleDisks([]*compute.Disk{{Name: name}}, inst)
		if err != nil {
			return nil, err
		}
		if err := vm.AddCustomNetwork(lbnet, lbsubnet); err != nil {
			return nil, err
		}
		if err := vm.SetPrivateIP(lbnet, ip); err != nil {
			return nil, err
		}
		vm.AddMetadata("enable-wsfc", "true")
		vm.RunTests(test)
		return inst, nil
	}
	mkbackend := func(name, ip, test string) error { _, err := mkvm(name, ip, test); return err }
	mkclient := func(name, ip, test string) error {
		inst, err := mkvm(name, ip, test)
		if err != nil {
			return err
		}
		inst.Scopes = append(inst.Scopes, "https://www.googleapis.com/auth/cloud-platform")
		return nil
	}

	if err := mkbackend("adbackend1", adBackend1IP4Addr, "TestWSFCBackend"); err != nil {
		return err
	}
	if err := mkbackend("adbackend2", adBackend2IP4Addr, "TestWSFCBackend"); err != nil {
		return err
	}
	if err := mkclient("adcontroller", adControllerIP4Addr, "TestWSFCClient"); err != nil {
		return err
	}
	return nil
}
