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

func dhcpServerStart(netns ns.NetNS, leaseIP, serverIP net.IP, stopCh <-chan bool) (*sync.WaitGroup, error) {
	// Add the expected IP to the pool
	lp := memorypool.MemoryPool{}
	err := lp.AddLease(leasepool.Lease{IP: dhcp4.IPAdd(net.IPv4(192, 168, 1, 5), 0)})
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
	hostVethName string = "dhcp0"
	contVethName string = "mccdbg0"
	pidfilePath  string = "/var/run/cni/dhcp-client.pid"
)

var _ = BeforeSuite(func() {
	println("mcc:  BeforeSuite deleted socketPath at: ", time.Now().String())
	os.Remove(socketPath)
	os.Remove(pidfilePath)
})

var _ = AfterSuite(func() {
	println("mcc:  AfterSuite deleted socketPath at: ", time.Now().String())
	os.Remove(socketPath)
	os.Remove(pidfilePath)
})

var _ = Describe("DHCP Operations", func() {
	var originalNS, targetNS ns.NetNS
	var dhcpServerStopCh chan bool
	var dhcpServerDone *sync.WaitGroup
	var clientCmd *exec.Cmd

	BeforeEach(func() {
		dhcpServerStopCh = make(chan bool)

		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		println("mcc: originalNS is ", originalNS.Path())

		targetNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
		println("mcc: targetNS is ", targetNS.Path())

		serverIP := net.IPNet{
			IP:   net.IPv4(192, 168, 1, 1),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		}

		// Create a veth pair in the "host" (original) NS
		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err = netlink.LinkAdd(&netlink.Veth{
				LinkAttrs: netlink.LinkAttrs{
					Name: hostVethName,
				},
				PeerName: contVethName,
			})
			Expect(err).NotTo(HaveOccurred())

			host, err := netlink.LinkByName(hostVethName)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.LinkSetUp(host)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.AddrAdd(host, &netlink.Addr{IPNet: &serverIP})
			Expect(err).NotTo(HaveOccurred())
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: host.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst: &net.IPNet{
					IP:   net.IPv4(0, 0, 0, 0),
					Mask: net.IPv4Mask(0, 0, 0, 0),
				},
			})
			Expect(err).NotTo(HaveOccurred())

			cont, err := netlink.LinkByName(contVethName)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.LinkSetNsFd(cont, int(targetNS.Fd()))
			Expect(err).NotTo(HaveOccurred())

			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		// Move the container side to the container's NS
		err = targetNS.Do(func(_ ns.NetNS) error {
			defer GinkgoRecover()

			link, err := netlink.LinkByName(contVethName)
			Expect(err).NotTo(HaveOccurred())
			err = netlink.LinkSetUp(link)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})

		// Start the DHCP server
		dhcpServerDone, err = dhcpServerStart(originalNS, net.IPv4(192, 168, 1, 5), serverIP.IP, dhcpServerStopCh)
		Expect(err).NotTo(HaveOccurred())
		println("mcc: dhcpServerStart-ed! at ", time.Now().String())
		_, errStartSP := os.Stat(socketPath)
		if errStartSP != nil {
			println("mcc: socketPath dhcpServerStart error - socketPath not created?? - time = ", time.Now().String())
		} else {
			println("mcc: socketPath dhcpServerStart DID create socketPath - time = ", time.Now().String())
		}

		// Start the DHCP client daemon
		os.MkdirAll(pidfilePath, 0755)
		dhcpPluginPath, err := exec.LookPath("dhcp")
		Expect(err).NotTo(HaveOccurred())
		clientCmd = exec.Command(dhcpPluginPath, "daemon")
		err = clientCmd.Start()
		Expect(err).NotTo(HaveOccurred())
		Expect(clientCmd.Process).NotTo(BeNil())

		start := time.Now()
		println("mcc: Starting to wait for socket")
		// Wait up to 15 seconds for the client socket
		Eventually(func() bool {
			_, err := os.Stat(socketPath)
			return err == nil
		}, time.Second*15, time.Second/4).Should(BeTrue())
		stop := time.Now()
		diff := stop.Sub(start)
		println("mcc: Time waited for socketPath (nanoseconds) was: ", diff.Nanoseconds())
		println("mcc: Time waited for socketPath (seconds) was: ", diff.Seconds())
	})

	AfterEach(func() {
		dhcpServerStopCh <- true
		dhcpServerDone.Wait()
		clientCmd.Process.Kill()
		clientCmd.Wait()

		Expect(originalNS.Close()).To(Succeed())
		Expect(targetNS.Close()).To(Succeed())
		println("mcc:  AfterEach deleted socketPath at: ", time.Now().String())
		os.Remove(socketPath)
		os.Remove(pidfilePath)
	})

	It("configures and deconfigures a link with ADD/DEL", func() {
		conf := `{
    "cniVersion": "0.3.1",
    "name": "mynet",
    "type": "ipvlan",
    "ipam": {
        "type": "dhcp"
    }
}`

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      contVethName,
			StdinData:   []byte(conf),
		}

		var addResult *current.Result
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				_, errAddSP := os.Stat(socketPath)
				if errAddSP != nil {
					println("mcc: socketPath Add error - socketPath not found", errAddSP)
				} else {
					println("mcc: socketPath Add did find socketPath", errAddSP)
				}
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

		err = originalNS.Do(func(ns.NetNS) error {
			return testutils.CmdDelWithArgs(args, func() error {
				_, errDelSP := os.Stat(socketPath)
				if errDelSP != nil {
					println("mcc: socketPath Del error - socketPath not found", errDelSP)
				} else {
					println("mcc: socketPath Del did find socketPath", errDelSP)
				}
				return cmdDel(args)
			})
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("correctly handles multiple DELs for the same container", func() {
		conf := `{
    "cniVersion": "0.3.1",
    "name": "mynet",
    "type": "ipvlan",
    "ipam": {
        "type": "dhcp"
    }
}`

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNS.Path(),
			IfName:      contVethName,
			StdinData:   []byte(conf),
		}

		var addResult *current.Result
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			r, _, err := testutils.CmdAddWithArgs(args, func() error {
				_, errAddSP := os.Stat(socketPath)
				if errAddSP != nil {
					println("mcc: socketPath Add error - socketPath not found", errAddSP)
				} else {
					println("mcc: socketPath Add did find socketPath", errAddSP)
				}
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

		wg := sync.WaitGroup{}
		wg.Add(3)
		started := sync.WaitGroup{}
		started.Add(3)
		for i := 0; i < 3; i++ {
			go func() {
				defer GinkgoRecover()

				// Wait until all goroutines are running
				started.Done()
				started.Wait()

				err = originalNS.Do(func(ns.NetNS) error {
					return testutils.CmdDelWithArgs(args, func() error {
						_, errDel1SP := os.Stat(socketPath)
						if errDel1SP != nil {
							println("mcc: socketPath Del 1 error - socketPath not found", errDel1SP)
						} else {
							println("mcc: socketPath Del 1 did find socketPath", errDel1SP)
						}
						return cmdDel(args)
					})
				})
				Expect(err).NotTo(HaveOccurred())
				wg.Done()
			}()
		}
		wg.Wait()

		err = originalNS.Do(func(ns.NetNS) error {
			return testutils.CmdDelWithArgs(args, func() error {
				_, errDel2SP := os.Stat(socketPath)
				if errDel2SP != nil {
					println("mcc: socketPath Del 2 error - socketPath not found", errDel2SP)
				} else {
					println("mcc: socketPath Del 2 did find socketPath", errDel2SP)
				}
				return cmdDel(args)
			})
		})
		Expect(err).NotTo(HaveOccurred())
	})
})
