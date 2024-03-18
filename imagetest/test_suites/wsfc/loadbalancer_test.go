//go:build cit
// +build cit

package wsfc

import (
	"testing"

	"github.com/GoogleCloudPlatform/guest-test-infra/imagetest/utils"
)

func TestBackend(t *testing.T) { utils.RunLoadBalancerBackend(t, wsfcVIP) }

func TestClient(t *testing.T) {
	ctx := utils.Context(t)
	utils.WaitForLoadBalancerBackends(ctx, t, adBackend1IP4Addr, adBackend2IP4Addr)
	utils.SetupLoadBalancer(ctx, t, utils.WSFCLoadBalancer, "adbackend1", "adbackend2", wsfcVIP)
	utils.CheckBackendsInLoadBalancer(ctx, t, wsfcVIP)
}
