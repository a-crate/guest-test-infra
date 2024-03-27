//go:build cit
// +build cit

package wsfc

import (
	"time"
	"os"
	"fmt"
	"testing"

	"github.com/GoogleCloudPlatform/guest-test-infra/imagetest/utils"
)


func TestBackend(t *testing.T) {
	utils.WindowsOnly(t)
	ctx := utils.Context(t)
	if controllerPrivateIP, err := os.ReadFile(`C:\image_test\ad_join_ok.txt`); err == nil {
		ip, err := utils.GetMetadata(ctx, "instance", "attributes", "use-static-ip")
		if err != nil {
			t.Fatalf("could not fetch static ip: %v", err)
		}
		out, err := utils.RunPowershellCmd(fmt.Sprintf(`netsh interface ip set address name=Ethernet static %s 255.255.255.0 10.1.2.1`, ip))
		if err != nil {
			t.Fatalf("error setting static ip %s: %s %s %v", ip, out.Stdout, out.Stderr, err)
		}
		out, err = utils.RunPowershellCmd(fmt.Sprintf(`netsh interface ip set dns name=Ethernet static %s`, controllerPrivateIP))
		if err != nil {
			t.Fatalf("error setting dns server to ip %s: %s %s %v", controllerPrivateIP, out.Stdout, out.Stderr, err)
		}
		out, err = utils.RunPowershellCmd(`ipconfig /flushdns`)
		if err != nil {
			t.Fatalf("error flushing dns: %s %s %v", out.Stdout, out.Stderr, err)
		}
		out, err = utils.RunPowershellCmd(`ipconfig /registerdns`)
		if err != nil {
			t.Fatalf("error registering dns: %s %s %v", out.Stdout, out.Stderr, err)
		}
	}
	utils.RunLoadBalancerBackend(ctx, t, utils.WSFCLoadBalancer, wsfcVIP)
}

func TestClient(t *testing.T) {
	utils.WindowsOnly(t)
	ctx := utils.Context(t)
	passwd, err := utils.GetMetadata(ctx, "instance", "attributes", "admin-passwd")
	if err != nil {
		t.Errorf("could not fetch password: %v", err)
	}
	out, err := utils.RunPowershellCmd(fmt.Sprintf(`New-ADUser -Name %s -AccountPassword (ConvertTo-SecureString -String "%s" -AsPlainText -Force) -Enabled $true`, domainuser_without_domain, passwd))
	if err != nil {
		t.Errorf("error adding user %s with password %s: %s %s %v", domainuser_without_domain, passwd, out.Stdout, out.Stderr, err)
	}
	out, err = utils.RunPowershellCmd(fmt.Sprintf(`Add-ADGroupMember -Members %s -Identity Administrators`, domainuser_without_domain))
	if err != nil {
		t.Errorf("error adding %s to domain admins: %s %s %v", domainuser_without_domain, out.Stdout, out.Stderr, err)
	}
	backend1, err := utils.GetRealVMName("adbackend1")
	if err != nil {
		t.Fatalf("could not get name of adbackend1: %s", err)
	}
	backend2, err := utils.GetRealVMName("adbackend2")
	if err != nil {
		t.Fatalf("could not get name of adbackend2: %s", err)
	}
	utils.WaitForLoadBalancerBackends(ctx, t, adBackend1IP4Addr, adBackend2IP4Addr)
	utils.JoinADNodes(ctx, t, adControllerIP4Addr, adBackend1IP4Addr, adBackend2IP4Addr, domain, domainuser, passwd)
	utils.JoinWSFC(ctx, t, adBackend1IP4Addr, fmt.Sprintf("%s.%s", backend1, domain), fmt.Sprintf("%s.%s", backend2, domain), domainuser, passwd, wsfcVIP)
	utils.SetupLoadBalancer(ctx, t, utils.WSFCLoadBalancer, "adbackend1", "adbackend2", wsfcVIP)
//	utils.CheckBackendsInLoadBalancer(ctx, t, wsfcVIP, "adbackend1", "adbackend2")
	r, err := utils.GetLBTargetWithTimeout(ctx, time.Second, wsfcVIP, "")
	t.Logf("got %q from lb", r)
	if err != nil {
		t.Errorf("couldn't get response from wsfcVIP: %v", err)
	}
	utils.GetLBTargetWithTimeout(ctx, time.Second, adBackend1IP4Addr, "stop")
	utils.GetLBTargetWithTimeout(ctx, time.Second, adBackend2IP4Addr, "stop")
}
