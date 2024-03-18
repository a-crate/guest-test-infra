//go:build cit
// +build cit

package l3loadbalancer

import (
	"testing"

	"github.com/GoogleCloudPlatform/guest-test-infra/imagetest/utils"
)

func TestL3Backend(t *testing.T) { utils.RunLoadBalancerBackend(t, l3IlbIP4Addr) }

func TestL3Client(t *testing.T) {
	ctx := utils.Context(t)
	utils.WaitForLoadBalancerBackends(ctx, t, l3backendVM1IP4addr, l3backendVM2IP4addr)
	utils.SetupLoadBalancer(ctx, t, utils.L3LoadBalancer, "l3backend1", "l3backend2", l3IlbIP4Addr)
	utils.CheckBackendsInLoadBalancer(ctx, t, l3IlbIP4Addr)
}
