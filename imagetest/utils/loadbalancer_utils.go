package utils

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/protobuf/proto"
)

// A collection of helper functions useful inside a VM when setting up a load
// balancer and checking for healthiness in CIT. Written with the assumption
// that they are all being used in conjuntion. It's advisable but not
// necessary to setup the load balancer on the VM that will checking the responses.

// LBLayer indicates to SetupLoadBalancer what kind to set up.
type LBLayer int
const (
	// L3 is a network passthrough passthrough load balancer
	L3LoadBalancer LBLayer = iota
	// L7 is an application load balancer.
	L7LoadBalancer
	// WSFCLoadBalancer is a network passthrough load balancer using WSFC health checks
	WSFCLoadBalancer
)

// RunLoadBalancerBackend starts serving http on port 80. It sends its hostname
// as a response to every connection, and shuts down when it receives a request
// with the body "stop". It will fail the test if it didn't receieve any
// requests to the IP of the load balancer.
func RunLoadBalancerBackend(t *testing.T, lbip string) {
	if IsWindows() {
		out, err := RunPowershellCmd(`New-NetFirewallRule -DisplayName 'open80inbound' -LocalPort 80 -Action Allow -Profile 'Public' -Protocol TCP -Direction Inbound`)
		if err != nil {
			t.Fatalf("could not allow inbound traffic on port 80: %s %s %v", out.Stdout, out.Stderr, err)
		}
		out, err = RunPowershellCmd(`New-NetFirewallRule -DisplayName 'open80outbound' -LocalPort 80 -Action Allow -Profile 'Public' -Protocol TCP -Direction Outbound`)
		if err != nil {
			t.Fatalf("could not allow outbound traffic on port 80: %s %s %v", out.Stdout, out.Stderr, err)
		}
	}
	ctx := Context(t)
	host, err := os.Hostname()
	if err != nil {
		t.Fatalf("could not get hostname: %v", err)
	}
	var mu sync.RWMutex
	var srv http.Server
	var count int
	c := make(chan struct{})
	stop := make(chan struct{})
	go func() {
	countloop:
		for {
			select {
			case <-c:
				count++
			case <-stop:
				break countloop
			}
		}
		mu.Lock()
		defer mu.Unlock()
		srv.Shutdown(ctx)
	}()
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		if req.Host == lbip {
			c <- struct{}{}
		}
		body, err := io.ReadAll(req.Body)
		io.WriteString(w, host)
		w.WriteHeader(http.StatusOK)
		if err == nil && string(body) == "stop" {
			stop <- struct{}{}
		}
	})
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		t.Errorf("Failed to serve http: %v", err)
	}
	if count < 1 {
		t.Errorf("Receieved zero requests through load balancer")
	}
}

// GetLBTargetWithTimeout is a helper for fetching the body of an http response from the given host
func GetLBTargetWithTimeout(ctx context.Context, t *testing.T, target string, body string) (string, error) {
	t.Helper()
	client := http.Client { Timeout: time.Second } // Same timeout health checks will have
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s/", target), strings.NewReader(body))
	if err != nil {
		t.Fatalf("failed to create http request to %s: %v", target, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err == io.EOF {
		err = nil
	}
	return string(respBody), err
}

// CheckBackendsInLoadBalancer ensures that two different healthy backends are in the target load balancer
func CheckBackendsInLoadBalancer(ctx context.Context, t *testing.T, lbip string) {
	var resp1, resp2 string
	for ctx.Err() == nil {
		time.Sleep(3 * time.Second) // Wait enough time for the health check and load balancer to update
		r, err := GetLBTargetWithTimeout(ctx, t, lbip, "stop")
		if err != nil || r == "no healthy upstream" {
			continue
		}
		if resp1 == "" {
			resp1 = r
			continue
		}
		resp2 = r
		break
	}
	if err := ctx.Err(); err != nil {
		t.Errorf("context expired making two successful http requests to load balancer: %v", err)
	}
	if resp1 == resp2 {
		t.Errorf("wanted different responses from both http requests, got %s for both", resp1)
	}
}

// WaitForLoadBalancerBackends waits for the two backends to be serving, and adds a cleanup
// step to stop them on failure when the test is done.
func WaitForLoadBalancerBackends(ctx context.Context, t *testing.T, backend1 string, backend2 string) {
	t.Cleanup(func() {
		if t.Failed() {
			GetLBTargetWithTimeout(ctx, t, backend1, "stop")
			GetLBTargetWithTimeout(ctx, t, backend2, "stop")
		}
	})
	wait := func(backend string) {
		for {
			if err := ctx.Err(); err != nil {
				t.Fatalf("test context expired before %s is serving: %v", backend, err)
			}
			_, err := GetLBTargetWithTimeout(ctx, t, backend, "")
			if err == nil {
				break
			}
		}
	}
	wait(backend1)
	wait(backend2)
}

// SetupLoadBalancer sets up a load balancer of the given type with two
// backends, using the given IP. Hostnames should be the testworkflow name, not
// the daisy name or the real name of the VM.
// (eg. backend, _ := t.CreateTestVM("vm1"); Should use "vm1" for the argument
// in this function.
//
// L3 load balancer architecture looks like this:
// Backend 1 (serving on port 80) --|
//                                  |--> Network Endpoint Group -> INTERNAL TCP backend <- TCP Forwarding Rule <- Client traffic
// Backend 2 (serving on port 80) --|    (GCE_VM_IP)               ^
//                                                                 |
//                                                            HTTP Health Check
// WSFC load balancer architecture is the same as L3, but uses a WSFC health check instead of an HTTP health check
//
// L7 load balancer architecture looks like this:
// Backend 1 (serving on port 80) --|
//                                  |--> Network Endpoint Group -> INTERNAL_MANAGED HTTP backend <- URL Map <- HTTP Proxy <- TCP Forwarding Rule <- Client traffic
// Backend 2 (serving on port 80) --|    (GCE_VM_IP_PORT)          ^
//                                                                 |
//                                                            HTTP Health Check
func SetupLoadBalancer(ctx context.Context, t *testing.T, lbType LBLayer, backend1, backend2, lbip string) {
	waitFor := func(op *compute.Operation, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%v", err)
		}
		if err := op.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	zone, err := GetMetadata(ctx, "instance", "zone")
	if err != nil {
		t.Fatalf("could not get zone: %v", err)
	}
	zone = path.Base(zone)
	project, err := GetMetadata(ctx, "project", "project-id")
	if err != nil {
		t.Fatalf("could not get project: %v", err)
	}
	backend1, err = GetRealVMName(backend1)
	if err != nil {
		t.Fatalf("could not get backend1 name: %v", err)
	}
	backend1, _, _ = strings.Cut(backend1, ".")
	backend2, err = GetRealVMName(backend2)
	if err != nil {
		t.Fatalf("could not get backend2 name: %v", err)
	}
	backend2, _, _ = strings.Cut(backend2, ".")
	// TODO: implement all necessary steps in daisy to do this inside the test framework
	negClient, err := compute.NewNetworkEndpointGroupsRESTClient(ctx)
	if err != nil {
		t.Fatalf("%v", err)
	}
	backendServiceClient, err := compute.NewRegionBackendServicesRESTClient(ctx)
	if err != nil {
		t.Fatalf("%v", err)
	}
	healthCheckClient, err := compute.NewRegionHealthChecksRESTClient(ctx)
	if err != nil {
		t.Fatalf("%v", err)
	}
	urlMapsClient, err := compute.NewRegionUrlMapsRESTClient(ctx)
	if err != nil {
		t.Fatalf("%v", err)
	}
	httpProxyClient, err := compute.NewRegionTargetHttpProxiesRESTClient(ctx)
	if err != nil {
		t.Fatalf("%v", err)
	}
	networkClient, err := compute.NewNetworksRESTClient(ctx)
	if err != nil {
		t.Fatalf("%v", err)
	}
	forwardingRuleClient, err := compute.NewForwardingRulesRESTClient(ctx)
	if err != nil {
		t.Fatalf("%v", err)
	}
	zoneClient, err := compute.NewZonesRESTClient(ctx)
	if err != nil {
		t.Fatalf("%v", err)
	}
	zoneGetReq := &computepb.GetZoneRequest{
		Project: project,
		Zone:    zone,
	}
	zoneproto, err := zoneClient.Get(ctx, zoneGetReq)
	if err != nil {
		t.Fatalf("%v", err)
	}
	region := path.Base(*zoneproto.Region)
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("%v", err)
	}
	network, err := GetMetadata(ctx, "instance", "network-interfaces", "0", "network")
	if err != nil {
		t.Fatalf("%v", err)
	}
	network = path.Base(network)
	networkGetReq := &computepb.GetNetworkRequest{
		Project: project,
		Network: network,
	}
	networkproto, err := networkClient.Get(ctx, networkGetReq)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var subnetwork string
	for _, subnetName := range networkproto.Subnetworks {
		if !strings.Contains(subnetName, "proxy") {
			subnetwork = subnetName
		}
	}
	network = *networkproto.SelfLink
	hostname, _, _ = strings.Cut(hostname, ".")
	negName := hostname + "-neg"
	healthCheckName := hostname + "-httphealthcheck"
	backendName := hostname + "-backend"
	urlMapName := hostname + "-urlmap"
	httpProxyName := hostname + "-httpproxy"
	forwardingRuleName := hostname + "-forwardingrule"

	t.Cleanup(func() {
		ctx := context.TODO() // we want to fire off attempts to clean up even if the test context has expired
		tryWait := func(op *compute.Operation, err error) {
			if err == nil {
				op.Wait(ctx)
			}
		}
		deleteFRReq := &computepb.DeleteForwardingRuleRequest{
			Project:        project,
			Region:         region,
			ForwardingRule: forwardingRuleName,
		}
		tryWait(forwardingRuleClient.Delete(ctx, deleteFRReq))
		if lbType == L7LoadBalancer { // Clean up extra resources from L7 load balancers
			deleteHttpProxyReq := &computepb.DeleteRegionTargetHttpProxyRequest{
				Project:         project,
				Region:          region,
				TargetHttpProxy: httpProxyName,
			}
			tryWait(httpProxyClient.Delete(ctx, deleteHttpProxyReq))
			deleteUrlMapReq := &computepb.DeleteRegionUrlMapRequest{
				Project: project,
				Region:  region,
				UrlMap:  urlMapName,
			}
			tryWait(urlMapsClient.Delete(ctx, deleteUrlMapReq))
		}
		deleteBEReq := &computepb.DeleteRegionBackendServiceRequest{ // Delete backend
			Project:        project,
			Region:         region,
			BackendService: backendName,
		}
		tryWait(backendServiceClient.Delete(ctx, deleteBEReq))
		// Delete health check
		deleteHcReq := &computepb.DeleteRegionHealthCheckRequest{
			Project:     project,
			Region:      region,
			HealthCheck: healthCheckName,
		}
		healthCheckClient.Delete(ctx, deleteHcReq)
		deleteNegReq := &computepb.DeleteNetworkEndpointGroupRequest{ // delete NEG
			Project:              project,
			Zone:                 zone,
			NetworkEndpointGroup: negName,
		}
		negClient.Delete(ctx, deleteNegReq)

		negClient.Close()
		healthCheckClient.Close()
		urlMapsClient.Close()
		networkClient.Close()
		zoneClient.Close()
		httpProxyClient.Close()
		backendServiceClient.Close()
		forwardingRuleClient.Close()
	})

	switch lbType {
	case WSFCLoadBalancer:
		fallthrough
	case L3LoadBalancer:
		// Create network endpoint group in lbnet and lbsubnet with GCE_VM_IP type
		neg := &computepb.NetworkEndpointGroup{
			Name:                &negName,
			NetworkEndpointType: proto.String("GCE_VM_IP"),
			Network:             &network,
			Subnetwork:          &subnetwork,
		}
		insertNegReq := &computepb.InsertNetworkEndpointGroupRequest{
			Project:                      project,
			Zone:                         zone,
			NetworkEndpointGroupResource: neg,
		}
		waitFor(negClient.Insert(ctx, insertNegReq))
	case L7LoadBalancer:
		// Create network endpoint group in lbnet and lbsubnet with GCE_VM_IP_PORT type
		neg := &computepb.NetworkEndpointGroup{
			Name:                &negName,
			NetworkEndpointType: proto.String("GCE_VM_IP_PORT"),
			Network:             &network,
			Subnetwork:          &subnetwork,
			DefaultPort:         proto.Int32(80),
		}
		insertNegReq := &computepb.InsertNetworkEndpointGroupRequest{
			Project:                      project,
			Zone:                         zone,
			NetworkEndpointGroupResource: neg,
		}
		waitFor(negClient.Insert(ctx, insertNegReq))
	}

	// Add instance endpoints of backend1 and backend2 to NEG
	backendsRes := &computepb.NetworkEndpointGroupsAttachEndpointsRequest{
		NetworkEndpoints: []*computepb.NetworkEndpoint{
			{Instance: proto.String(fmt.Sprintf("projects/%s/zones/%s/instances/%s", project, zone, backend1))},
			{Instance: proto.String(fmt.Sprintf("projects/%s/zones/%s/instances/%s", project, zone, backend2))},
		},
	}
	addBackendsReq := &computepb.AttachNetworkEndpointsNetworkEndpointGroupRequest{
		NetworkEndpointGroup: negName,
		NetworkEndpointGroupsAttachEndpointsRequestResource: backendsRes,
		Project: project,
		Zone:    zone,
	}
	waitFor(negClient.AttachNetworkEndpoints(ctx, addBackendsReq))

	var hcRes *computepb.HealthCheck
	switch lbType {
	case WSFCLoadBalancer:
		t.Fatal("TODO")
	case L3LoadBalancer:
		fallthrough
	case L7LoadBalancer:
		// Create http health on port 80
		httpHc := &computepb.HTTPHealthCheck{
			PortSpecification: proto.String("USE_FIXED_PORT"),
			Port:              proto.Int32(80),
		}
		hcRes = &computepb.HealthCheck{
			CheckIntervalSec: proto.Int32(1),
			TimeoutSec:       proto.Int32(1),
			Name:             &healthCheckName,
			HttpHealthCheck:  httpHc,
			Type:             proto.String("HTTP"),
		}
	}

	insertHealthCheckReq := &computepb.InsertRegionHealthCheckRequest{
		Project:             project,
		HealthCheckResource: hcRes,
		Region:              region,
	}
	waitFor(healthCheckClient.Insert(ctx, insertHealthCheckReq))

	switch lbType {
	case WSFCLoadBalancer:
		fallthrough
	case L3LoadBalancer:
		// Create INTERNAL tcp backend service with health check
		backendService := &computepb.BackendService{
			HealthChecks: []string{fmt.Sprintf("projects/%s/regions/%s/healthChecks/%s", project, region, healthCheckName)},
			Backends: []*computepb.Backend{
				{Group: proto.String(fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/zones/%s/networkEndpointGroups/%s", project, zone, negName))},
			},
			Name:                &backendName,
			LoadBalancingScheme: proto.String("INTERNAL"),
			Protocol:            proto.String("TCP"),
		}
		backendInsertReq := &computepb.InsertRegionBackendServiceRequest{
			Project:                project,
			BackendServiceResource: backendService,
			Region:                 region,
		}
		waitFor(backendServiceClient.Insert(ctx, backendInsertReq))

		// Create forwarding rule to send traffic to to the load balancer
		forwardingRule := &computepb.ForwardingRule{
			LoadBalancingScheme: proto.String("INTERNAL"),
			Network:             &network,
			Subnetwork:          &subnetwork,
			BackendService:      proto.String(fmt.Sprintf("projects/%s/regions/%s/backendServices/%s", project, region, backendName)),
			IPAddress:           &lbip,
			IPProtocol:          proto.String("TCP"),
			Ports:               []string{"80"},
			Name:                &forwardingRuleName,
		}
		forwardingRuleReq := &computepb.InsertForwardingRuleRequest{
			Project:                project,
			Region:                 region,
			ForwardingRuleResource: forwardingRule,
		}
		waitFor(forwardingRuleClient.Insert(ctx, forwardingRuleReq))
	case L7LoadBalancer:
		// Create INTERNAL_MANAGED http backend service with health check
		backendService := &computepb.BackendService{
			HealthChecks: []string{fmt.Sprintf("projects/%s/regions/%s/healthChecks/%s", project, region, healthCheckName)},
			Backends: []*computepb.Backend{
				{
					Group:              proto.String(fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/zones/%s/networkEndpointGroups/%s", project, zone, negName)),
					BalancingMode:      proto.String("RATE"),
					MaxRatePerEndpoint: proto.Float32(512),
				},
			},
			Name:                &backendName,
			LoadBalancingScheme: proto.String("INTERNAL_MANAGED"),
			Protocol:            proto.String("HTTP"),
		}
		backendInsertReq := &computepb.InsertRegionBackendServiceRequest{
			Project:                project,
			BackendServiceResource: backendService,
			Region:                 region,
		}
		waitFor(backendServiceClient.Insert(ctx, backendInsertReq))

		// Create URL map to route requests to the backend
		insertUrlMapReq := &computepb.InsertRegionUrlMapRequest{
			Project: project,
			Region:  region,
			UrlMapResource: &computepb.UrlMap{
				Name:           &urlMapName,
				DefaultService: proto.String(fmt.Sprintf("projects/%s/regions/%s/backendServices/%s", project, region, backendName)),
			},
		}
		waitFor(urlMapsClient.Insert(ctx, insertUrlMapReq))

		// Create http proxy to route requests to the url map
		proxyInsertReq := &computepb.InsertRegionTargetHttpProxyRequest{
			Project: project,
			Region:  region,
			TargetHttpProxyResource: &computepb.TargetHttpProxy{
				Name:   &httpProxyName,
				UrlMap: proto.String(fmt.Sprintf("projects/%s/regions/%s/urlMaps/%s", project, region, urlMapName)),
			},
		}
		waitFor(httpProxyClient.Insert(ctx, proxyInsertReq))

		// Create forwarding rule to send traffic to to the proxy
		forwardingRule := &computepb.ForwardingRule{
			LoadBalancingScheme: proto.String("INTERNAL_MANAGED"),
			Network:             &network,
			Subnetwork:          &subnetwork,
			Target:              proto.String(fmt.Sprintf("projects/%s/regions/%s/targetHttpProxies/%s", project, region, httpProxyName)),
			IPAddress:           &lbip,
			IPProtocol:          proto.String("TCP"),
			PortRange:           proto.String("80"),
			Name:                &forwardingRuleName,
		}
		forwardingRuleReq := &computepb.InsertForwardingRuleRequest{
			Project:                project,
			Region:                 region,
			ForwardingRuleResource: forwardingRule,
		}
		waitFor(forwardingRuleClient.Insert(ctx, forwardingRuleReq))
	}
}
