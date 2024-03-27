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
// balancer and checking for healthiness in CIT. Written with the assumption // that they are all being used in conjuntion. It's advisable but not // necessary to setup the load balancer on the VM that will checking the responses.

// LBType indicates to utility functions what kind of load balancer is under test
type LBType int
const (
	// L3 is a network passthrough passthrough load balancer
	L3LoadBalancer LBType = iota
	// L7 is an application load balancer.
	L7LoadBalancer
	// WSFCLoadBalancer is a network passthrough load balancer using WSFC health checks
	WSFCLoadBalancer
)

// RunLoadBalancerBackend starts serving http on port 80. It sends its hostname
// as a response to every connection, and shuts down when it receives a request
// with the body "stop". It will fail the test if it didn't receieve any
// requests sent to the IP of the load balancer.
func RunLoadBalancerBackend(ctx context.Context, t *testing.T, lbType LBType, lbip string) {
	if IsWindows() {
		addOrFail := func(cmd string) {
			t.Helper()
			if out, err := RunPowershellCmd(cmd); err != nil {
				t.Fatalf("could not add firewall rule: %s %s %v", out.Stdout, out.Stderr, err)
			}
		}
		addOrFail(`New-NetFirewallRule -DisplayName 'open80inbound' -LocalPort 80 -Action Allow -Protocol TCP -Direction Inbound`)
		addOrFail(`New-NetFirewallRule -DisplayName 'open80outbound' -LocalPort 80 -Action Allow -Protocol TCP -Direction Outbound`)
		if lbType == WSFCLoadBalancer {
			addOrFail(`New-NetFirewallRule -DisplayName 'wsfchealthcheckinbound' -LocalPort 59998 -Action Allow -Protocol TCP -Direction Inbound`)
			addOrFail(`New-NetFirewallRule -DisplayName 'wsfchealthcheckoutbound' -LocalPort 59998 -Action Allow -Protocol TCP -Direction Outbound`)
		}
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatalf("could not get hostname: %v", err)
	}
	var mu sync.RWMutex
	var srv http.Server
	var count int
	commands := make(chan string, 1)
	go func() {
commandloop:
		for {
			cmd := <- commands
			switch cmd {
			case "count":
				count++
			case "stop":
				break commandloop
			case "reboot":
				mu.Lock()
				RunPowershellCmd(`Restart-Computer -Force`)
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
			commands <- "count"
		}
		b, err := io.ReadAll(req.Body)
		body := string(b)
		if err != nil {
			return
		} else if body == "stop" {
			commands <- "stop"
		} else if body == "reboot" {
			commands <- "reboot"
		} else if lbType == WSFCLoadBalancer && strings.HasPrefix(body, "join ") {
			joinOpts := strings.Split(body, " ")
			if len(joinOpts) != 5 {
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, "bad join request")
				return
			}
			// The join message must be sent twice (with a reboot between) to finish the join
			// Should be format "join domain controllerIP domain\user adminpassword"
			// ex "join domain.example.com 10.0.0.1 domain.example.com\TestAdmin adminpassword"
			domain := joinOpts[1]
			controllerPrivateIP := joinOpts[2]
			domainUser := joinOpts[3]
			passwd := joinOpts[4]
			if _, err := os.Stat(`C:\image_test\ad_join_ok.txt`); err != nil {
				out, err := RunPowershellCmd(fmt.Sprintf(`Set-DnsClientServerAddress -ServerAddresses ("%s") -PassThru -InterfaceAlias "Ethernet"`, controllerPrivateIP))
				if err != nil {
					err = fmt.Errorf("error setting dns server to ad controller: %s %s %v", out.Stdout, out.Stderr, err)
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					io.WriteString(w, err.Error())
					return
				}
				out, err = RunPowershellCmd(`ipconfig /flushdns`)
				if err != nil {
					err = fmt.Errorf("error flushing dns: %s %s %v", out.Stdout, out.Stderr, err)
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					io.WriteString(w, err.Error())
					return
				}
				out, err = RunPowershellCmd(`ipconfig /registerdns`)
				if err != nil {
					err = fmt.Errorf("error registering dns: %s %s %v", out.Stdout, out.Stderr, err)
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					io.WriteString(w, err.Error())
					return
				}
				for  {
					out, err := RunPowershellCmd(fmt.Sprintf(`Add-Computer -DomainName %s -Force -Credential (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "%s", (ConvertTo-SecureString -String '%s' -AsPlainText -Force))`, domain, domainUser, passwd))
					if err == nil {
						break
					}
					if ctxerr := req.Context().Err(); ctxerr != nil {
						err = fmt.Errorf("context expired before domain could be joined: %v (last attempt: %s %s %v)", ctxerr, out.Stdout, out.Stderr, err)
						t.Error(err)
						w.WriteHeader(http.StatusInternalServerError)
						io.WriteString(w, err.Error())
						return
					}
					time.Sleep(time.Second)
				}
				if err = os.MkdirAll(`C:\image_test\`, 0777); err != nil {
					err = fmt.Errorf("could not make image_test directory: %v", err)
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					io.WriteString(w, err.Error())
					return
				}
				if err = os.WriteFile(`C:\image_test\ad_join_ok.txt`, []byte(""), 0777); err != nil {
					err = fmt.Errorf("could not create ad_join_ok.txt: %s", err)
					t.Error(err)
					w.WriteHeader(http.StatusInternalServerError)
					io.WriteString(w, err.Error())
					return
				}
				commands <- "reboot"
				w.WriteHeader(http.StatusOK)
				io.WriteString(w, host)
				return
			}
			// Make the domain admin a local administrator
			out, err := RunPowershellCmd(fmt.Sprintf(`net localgroup administrators %s /add`, domainUser))
			if err != nil {
				err = fmt.Errorf("error making %s local admin: %s %s %v", domainUser, out.Stdout, out.Stderr, err)
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, err.Error())
				return
			}
		} else if lbType == WSFCLoadBalancer && strings.HasPrefix(body, "make-wsfc") {
			wsfcOpts := strings.Split(body, " ")
			if len(wsfcOpts) != 6 {
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, "bad make-wsfc request")
				return
			}
			// ex "make-wsfc ad-backend1.domain.example.com ad-backend2.domain.example.com TestAdmin adminpassword 10.0.0.100"
			backend1 := wsfcOpts[1]
			backend2 := wsfcOpts[2]
			user := wsfcOpts[3]
			passwd := wsfcOpts[4]
			clusterVIP := wsfcOpts[5]
			out, err := RunPowershellCmd(fmt.Sprintf(`schtasks.exe /Create /TN newcluster /SC DAILY /MO 1 /S %s /RU %s /RP "%s" /TR "powershell.exe New-Cluster -Name wsfc_cluster -Node %s, %s -NoStorage -StaticAddress %s"`, backend1, user, passwd, backend1, backend2, clusterVIP))
			if err != nil {
				err = fmt.Errorf("error making cluster creation task: %s %s %v", out.Stdout, out.Stderr, err)
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, err.Error())
				return
			}
			out, err = RunPowershellCmd(`schtasks.exe /run /tn newcluster`)
			if err != nil {
				err = fmt.Errorf("error starting cluster creation task: %s %s %v", out.Stdout, out.Stderr, err)
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, err.Error())
				return
			}
			for {
				if err := ctx.Err(); err != nil {
					t.Fatalf("test context expired before cluster creation finished: %s", err)
				}
				out, err := RunPowershellCmd(`Get-Cluster`)
				if err != nil {
					time.Sleep(2 * time.Second)
					continue
				}
				t.Logf("got cluster: %s %s %v", out.Stdout, out.Stderr, err)
				break
			}
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, host)
	})
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		t.Errorf("Failed to serve http: %v", err)
	}
	if count < 1 {
		t.Errorf("Receieved zero requests through load balancer")
	}
}

// GetLBTargetWithTimeout is a helper for fetching the body of an http response from the given host
func GetLBTargetWithTimeout(ctx context.Context, t time.Duration, target string, reqbody string) (string, error) {
	client := http.Client { Timeout: t }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s/", target), strings.NewReader(reqbody))
	if err != nil {
		return "", err
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
	if err == nil && resp.StatusCode != 200 {
		err = fmt.Errorf("non-200 status: %s", resp.Status)
	}
	return string(respBody), err
}

// CheckBackendsInLoadBalancer ensures that the target backends are in the load
// balancer. Backend name should be testworkflow names, not daisy names or
// actual VM names.
func CheckBackendsInLoadBalancer(ctx context.Context, t *testing.T, lbip string, backends ...string) {
	backendNames := make(map[string]string)
	backendStatus := make(map[string]bool)
	for _, backend := range backends {
		name, err := GetRealVMName(backend)
		if err != nil {
			t.Errorf("could not check for %s in loadbalancer, could not determine name: %v", err)
			continue
		}
		backendNames[backend] = name
		backendStatus[name] = false
	}
	for ctx.Err() == nil {
		time.Sleep(3 * time.Second) // Wait enough time for the health check and load balancer to update
		resp, err := GetLBTargetWithTimeout(ctx, time.Second, lbip, "stop")
		if err != nil || resp == "no healthy upstream" || resp == "" {
			continue
		}
		backendStatus[backendNames[resp]] = true
		allOK := true
		for _, backend := range backends {
			if !backendStatus[backendNames[backend]] {
				allOK = false
				break
			}
		}
		if allOK {
			continue
		}
	}
	if err := ctx.Err(); err != nil {
		t.Errorf("context expired before finding all backends in load balancer: %v", err)
	}
	for _, backend := range backends {
		if !backendStatus[backendNames[backend]] {
			t.Errorf("could not find %s in load balancer", backend)
		}
	}
}

// WaitForLoadBalancerBackends waits for the two backends to be serving, and adds a cleanup
// step to stop them on failure when the test is done.
func WaitForLoadBalancerBackends(ctx context.Context, t *testing.T, backend1 string, backend2 string) {
	t.Cleanup(func() {
		GetLBTargetWithTimeout(ctx, time.Second, backend1, "stop")
		GetLBTargetWithTimeout(ctx, time.Second, backend2, "stop")
	})
	wait := func(backend string) {
		for {
			if err := ctx.Err(); err != nil {
				t.Fatalf("test context expired before %s is serving: %v", backend, err)
			}
			_, err := GetLBTargetWithTimeout(ctx, time.Second, backend, "")
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
// WSFC load balancer architecture is the same as L3, but uses a TCP health check to communicate with guest agent
// See https://cloud.google.com/compute/docs/tutorials/running-windows-server-failover-clustering#configure_the_backend
//
// L7 load balancer architecture looks like this:
// Backend 1 (serving on port 80) --|
//                                  |--> Network Endpoint Group -> INTERNAL_MANAGED HTTP backend <- URL Map <- HTTP Proxy <- TCP Forwarding Rule <- Client traffic
// Backend 2 (serving on port 80) --|    (GCE_VM_IP_PORT)          ^
//                                                                 |
//                                                            HTTP Health Check
func SetupLoadBalancer(ctx context.Context, t *testing.T, lbType LBType, backend1, backend2, lbip string) {
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
		tcpHc := &computepb.TCPHealthCheck{
			PortSpecification: proto.String("USE_FIXED_PORT"),
			Port:              proto.Int32(59998),
			Request: &lbip,
			Response: proto.String("1"),
		}
		hcRes = &computepb.HealthCheck{
			CheckIntervalSec: proto.Int32(1),
			TimeoutSec:       proto.Int32(1),
			Name:             &healthCheckName,
			TcpHealthCheck:  tcpHc,
			Type:             proto.String("TCP"),
		}
	case L3LoadBalancer:
		fallthrough
	case L7LoadBalancer:
		// Create http health check on port 80
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


// JoinADNodes will instruct backend1 and backend2 to join the domain, and
// fail the test if there is an error in this process. Backends must be serving
// HTTP for this to succeed. The username given must have permission to add
// nodes the domain and be in the form domain\username.
func JoinADNodes(ctx context.Context, t *testing.T, controllerIP, backend1Addr, backend2Addr, domain, domainuser, adminpassword string) {
	timeout := 30 * time.Minute
	if deadline, ok := t.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	r, err := GetLBTargetWithTimeout(ctx, timeout, backend1Addr, fmt.Sprintf("join %s %s %s %s", domain, controllerIP, domainuser, adminpassword))
	if err != nil {
		t.Fatalf("could not configure dns and join domain on %s: %s %v", backend1Addr, r, err)
	}
	r, err = GetLBTargetWithTimeout(ctx, timeout, backend2Addr, fmt.Sprintf("join %s %s %s %s", domain, controllerIP, domainuser, adminpassword))
	if err != nil {
		t.Fatalf("could not configure dns and join domain on %s: %s %v", backend2Addr, r, err)
	}
	time.Sleep(time.Second)
	WaitForLoadBalancerBackends(ctx, t, backend1Addr, backend2Addr)

	r, err = GetLBTargetWithTimeout(ctx, timeout, backend1Addr, fmt.Sprintf("join %s %s %s %s", domain, controllerIP, domainuser, adminpassword))
	if err != nil {
		t.Fatalf("could not verify domain credentials on %s: %s %v", backend1Addr, r, err)
	}
	r, err = GetLBTargetWithTimeout(ctx, timeout, backend2Addr, fmt.Sprintf("join %s %s %s %s", domain, controllerIP, domainuser, adminpassword))
	if err != nil {
		t.Fatalf("could not verify domain credentials on %s: %s %v", backend2Addr, r, err)
	}
}

// JoinWSFC instructs a backend to create a failover cluster using the account
// and password and add the two named backends (in FQDN form) to it, failing if
// this is unsuccessful. The backend must be serving HTTP.
func JoinWSFC(ctx context.Context, t *testing.T, backend1Addr, backend1Name, backend2Name, domainUser, password, clusterVIP string) {
	timeout := 30 * time.Minute
	if deadline, ok := t.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	r, err := GetLBTargetWithTimeout(ctx, timeout, backend1Addr, fmt.Sprintf("make-wsfc %s %s %s %s %s", backend1Name, backend2Name, domainUser, password, clusterVIP))
	if err != nil {
		t.Fatalf("could not make wsfc: %s %v", r, err)
	}
}
