//go:build cit
// +build cit

package l7loadbalancer

import (
	"testing"

	"github.com/GoogleCloudPlatform/guest-test-infra/imagetest/utils"
)

func TestL7Backend(t *testing.T) { utils.RunLoadBalancerBackend(t, l7IlbIP4Addr) }

func TestL7Client(t *testing.T) {
	ctx := utils.Context(t)
	utils.WaitForLoadBalancerBackends(ctx, t, l7backendVM1IP4addr, l7backendVM2IP4addr)
	utils.SetupLoadBalancer(ctx, t, utils.L7LoadBalancer, "l7backend1", "l7backend2", l7IlbIP4Addr)
	utils.CheckBackendsInLoadBalancer(ctx, t, l7IlbIP4Addr)
}
