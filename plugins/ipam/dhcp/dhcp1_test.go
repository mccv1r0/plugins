// Copyright 2015-2018 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"

	"github.com/vishvananda/netlink"

	"github.com/d2g/dhcp4"
	"github.com/d2g/dhcp4server"
	"github.com/d2g/dhcp4server/leasepool"
	"github.com/d2g/dhcp4server/leasepool/memorypool"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func dhcpServerStart1(netns ns.NetNS, leaseIP, serverIP net.IP, stopCh <-chan bool) (*sync.WaitGroup, error) {
	// Add the expected IP to the pool
	lp := memorypool.MemoryPool{}
	//err := lp.AddLease(leasepool.Lease{IP: dhcp4.IPAdd(net.IPv4(192, 168, 1, 5), 0)})
	//err := lp.AddLease(leasepool.Lease{IP: dhcp4.IPAdd(net.IPv4(192, 168, 1, 4), 0)})
	err := lp.AddLease(leasepool.Lease{IP: dhcp4.IPAdd(leaseIP, 0)})
	if err != nil {
		return nil, fmt.Errorf("error adding IP to DHCP pool: %v", err)
	}

	dhcpServer, err := dhcp4server.New(
		net.IPv4(192, 168, 1, 1),
		&lp,
		dhcp4server.SetLocalAddr(net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 67}),
		dhcp4server.SetRemoteAddr(net.UDPAddr{IP: net.IPv4bcast, Port: 68}),
		dhcp4server.LeaseDuration(time.Minute*15),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHCP server: %v", err)
	}

	stopWg := sync.WaitGroup{}
	stopWg.Add(2)
	startWg := sync.WaitGroup{}
	startWg.Add(2)

	// Run DHCP server in a goroutine so it doesn't block the main thread
	go func() {
		defer GinkgoRecover()

		err = netns.Do(func(ns.NetNS) error {
			startWg.Done()
			if err := dhcpServer.ListenAndServe(); err != nil {
				// Log, but don't trap errors; the server will
				// always report an error when stopped
				GinkgoT().Logf("DHCP server finished with error: %v", err)
			}
			return nil
		})
		stopWg.Done()
		// Trap any errors after the Done, to allow the main test thread
		// to continue and clean up.  Otherwise the test hangs.
		Expect(err).NotTo(HaveOccurred())
	}()

	// Stop DHCP server in another goroutine for the same reason
	go func() {
		startWg.Done()
		<-stopCh
		dhcpServer.Shutdown()
		stopWg.Done()
	}()
	startWg.Wait()

	return &stopWg, nil
}

const (
	hostBridgeName string = "dhcpbr0"
	hostVethName0  string = "br-eth0"
	contVethName0  string = "eth0"
	hostVethName1  string = "br-eth1"
	contVethName1  string = "eth1"
)

var _ = Describe("1: DHCP Lease Unavailable Operations", func() {
	var originalNS, targetNS ns.NetNS
	var dhcpServerStopCh chan bool
	var dhcpServerDone *sync.WaitGroup
	var clientCmd *exec.Cmd
	var socketPath string
	var tmpDir string
	var err error

	var br *netlink.Bridge

	BeforeEach(func() {
		dhcpServerStopCh = make(chan bool)

		tmpDir, err = getTmpDir()
		Expect(err).NotTo(HaveOccurred())
		socketPath = filepath.Join(tmpDir, "dhcp.sock")

		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		serverIP := net.IPNet{
			IP:   net.IPv4(192, 168, 1, 1),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		}

		// Use (original) NS
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			// Create bridge in the "host" (original) NS
			//linkAttrs := netlink.LinkAttrs{Name: hostBridgeName}
			//br = &netlink.Bridge{linkAttrs}
			br = &netlink.Bridge{
				LinkAttrs: netlink.LinkAttrs{
					Name: hostBridgeName,
				},
			}

			err = netlink.LinkAdd(br)
			Expect(err).NotTo(HaveOccurred())

			//err = netlink.AddrAdd(br, &netlink.Addr{IPNet: &serverIP})
			address := &netlink.Addr{IPNet: &net.IPNet{
				IP:   net.IPv4(192, 168, 1, 1),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			}}
			err = netlink.AddrAdd(br, address)
			Expect(err).NotTo(HaveOccurred())

			err = netlink.LinkSetUp(br)
			Expect(err).NotTo(HaveOccurred())

			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: br.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst: &net.IPNet{
					IP:   net.IPv4(0, 0, 0, 0),
					Mask: net.IPv4Mask(0, 0, 0, 0),
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// Create veth pair eth0
			vethLinkAttrs := netlink.NewLinkAttrs()
			vethLinkAttrs.Name = hostVethName0

			veth := &netlink.Veth{
				LinkAttrs: vethLinkAttrs,
				PeerName:  contVethName0,
			}
			err = netlink.LinkAdd(veth)
			Expect(err).NotTo(HaveOccurred())

			err = netlink.LinkSetUp(veth)
			Expect(err).NotTo(HaveOccurred())

			bridgeLink, err := netlink.LinkByName(hostBridgeName)
			Expect(err).NotTo(HaveOccurred())

			hostVethLink, err := netlink.LinkByName(hostVethName0)
			Expect(err).NotTo(HaveOccurred())

			err = netlink.LinkSetMaster(hostVethLink, bridgeLink.(*netlink.Bridge))
			Expect(err).NotTo(HaveOccurred())

			cont, err := netlink.LinkByName(contVethName0)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.LinkSetNsFd(cont, int(targetNS.Fd()))
			Expect(err).NotTo(HaveOccurred())

			// Create veth path - eth1
			vethLinkAttrs1 := netlink.NewLinkAttrs()
			vethLinkAttrs1.Name = hostVethName1

			veth1 := &netlink.Veth{
				LinkAttrs: vethLinkAttrs1,
				PeerName:  contVethName1,
			}
			err = netlink.LinkAdd(veth1)
			Expect(err).NotTo(HaveOccurred())

			err = netlink.LinkSetUp(veth1)
			Expect(err).NotTo(HaveOccurred())

			bridgeLink, err = netlink.LinkByName(hostBridgeName)
			Expect(err).NotTo(HaveOccurred())

			hostVethLink1, err := netlink.LinkByName(hostVethName1)
			Expect(err).NotTo(HaveOccurred())

			err = netlink.LinkSetMaster(hostVethLink1, bridgeLink.(*netlink.Bridge))
			Expect(err).NotTo(HaveOccurred())

			cont1, err := netlink.LinkByName(contVethName1)
			Expect(err).NotTo(HaveOccurred())

			err = netlink.LinkSetNsFd(cont1, int(targetNS.Fd()))
			Expect(err).NotTo(HaveOccurred())

			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Move the container side to the container's NS
		err = targetNS.Do(func(_ ns.NetNS) error {
			defer GinkgoRecover()

			link, err := netlink.LinkByName(contVethName0)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.LinkSetUp(link)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})

		// Start the DHCP server
		dhcpServerDone, err = dhcpServerStart1(originalNS, net.IPv4(192, 168, 1, 5), serverIP.IP, dhcpServerStopCh)
		Expect(err).NotTo(HaveOccurred())

		// Start the DHCP client daemon
		dhcpPluginPath, err := exec.LookPath("dhcp")
		Expect(err).NotTo(HaveOccurred())
		clientCmd = exec.Command(dhcpPluginPath, "daemon", "-socketpath", socketPath)
		err = clientCmd.Start()
		Expect(err).NotTo(HaveOccurred())
		Expect(clientCmd.Process).NotTo(BeNil())

		// Wait up to 15 seconds for the client socket
		Eventually(func() bool {
			_, err := os.Stat(socketPath)
			return err == nil
		}, time.Second*15, time.Second/4).Should(BeTrue())
	})

	AfterEach(func() {
		dhcpServerStopCh <- true
		dhcpServerDone.Wait()
		clientCmd.Process.Kill()
		clientCmd.Wait()

		Expect(originalNS.Close()).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
		defer os.RemoveAll(tmpDir)
	})

	It("Configures multiple links with multiple ADD with second lease unavailable", func() {
		conf := fmt.Sprintf(`{
	    "cniVersion": "0.3.1",
	    "name": "mynet",
	    "type": "bridge",
	    "bridge": "%s",
	    "ipam": {
	        "type": "dhcp",
		"daemonSocketPath": "%s"
	    }
	}`, hostBridgeName, socketPath)

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      contVethName0,
			StdinData:   []byte(conf),
		}

		var addResult *current.Result
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).NotTo(HaveOccurred())

			addResult, err = current.GetResult(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(addResult.IPs)).To(Equal(1))
			Expect(addResult.IPs[0].Address.String()).To(Equal("192.168.1.5/24"))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		args = &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      contVethName1,
			StdinData:   []byte(conf),
		}

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			_, _, err := testutils.CmdAddWithArgs(args, func() error {
				return cmdAdd(args)
			})
			Expect(err).To(HaveOccurred())
			println(err.Error())
			Expect(err.Error()).To(Equal("error calling DHCP.Allocate: no more tries"))
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		args = &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      contVethName1,
			StdinData:   []byte(conf),
		}

		err = originalNS.Do(func(ns.NetNS) error {
			return testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
		})
		Expect(err).NotTo(HaveOccurred())

		args = &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      contVethName0,
			StdinData:   []byte(conf),
		}

		err = originalNS.Do(func(ns.NetNS) error {
			return testutils.CmdDelWithArgs(args, func() error {
				return cmdDel(args)
			})
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
