// Copyright 2023 CNI authors
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
	"math"
	"net"
	"syscall"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

var _ = ginkgo.Describe("bandwidth config test", func() {
	var (
		hostNs          ns.NetNS
		containerNs     ns.NetNS
		ifbDeviceName   string
		hostIfname      string
		containerIfname string
		hostIP          net.IP
		containerIP     net.IP
		hostIfaceMTU    int
	)

	ginkgo.BeforeEach(func() {
		var err error

		hostIfname = "host-veth"
		containerIfname = "container-veth"

		hostNs, err = testutils.NewNS()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		containerNs, err = testutils.NewNS()
		gomega.Expect(err).NotTo(gomega.HaveOccurred())

		hostIP = net.IP{169, 254, 0, 1}
		containerIP = net.IP{10, 254, 0, 1}
		hostIfaceMTU = 1024
		ifbDeviceName = "bwpa8eda89404b7"

		createVeth(hostNs, hostIfname, containerNs, containerIfname, hostIP, containerIP, hostIfaceMTU)
	})

	ginkgo.AfterEach(func() {
		gomega.Expect(containerNs.Close()).To(gomega.Succeed())
		gomega.Expect(testutils.UnmountNS(containerNs)).To(gomega.Succeed())
		gomega.Expect(hostNs.Close()).To(gomega.Succeed())
		gomega.Expect(testutils.UnmountNS(hostNs)).To(gomega.Succeed())
	})

	// Bandwidth requires host-side interface info, and thus only
	// supports 0.3.0 and later CNI versions
	for _, ver := range []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0"} {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined ginkgo.It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		ginkgo.Describe("cmdADD", func() {
			ginkgo.It(fmt.Sprintf("[%s] fails with invalid UnshapedSubnets", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 123,
			"ingressBurst": 123,
			"egressRate": 123,
			"egressBurst": 123,
			"unshapedSubnets": ["10.0.0.0/8", "hello"],
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      "eth0",
					StdinData:   []byte(conf),
				}

				gomega.Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer ginkgo.GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					gomega.Expect(err).To(gomega.MatchError("bad subnet \"hello\" provided, details invalid CIDR address: hello"))
					return nil
				})).To(gomega.Succeed())
			})

			ginkgo.It(fmt.Sprintf("[%s] fails with invalid ShapedSubnets", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 123,
			"ingressBurst": 123,
			"egressRate": 123,
			"egressBurst": 123,
			"ShapedSubnets": ["10.0.0.0/8", "hello"],
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      "eth0",
					StdinData:   []byte(conf),
				}

				gomega.Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer ginkgo.GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					gomega.Expect(err).To(gomega.MatchError("bad subnet \"hello\" provided, details invalid CIDR address: hello"))
					return nil
				})).To(gomega.Succeed())
			})

			ginkgo.It(fmt.Sprintf("[%s] fails with both ShapedSubnets and UnshapedSubnets specified", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 123,
			"ingressBurst": 123,
			"egressRate": 123,
			"egressBurst": 123,
			"shapedSubnets": ["10.0.0.0/8"],
			"unshapedSubnets": ["192.168.0.0/16"],
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      "eth0",
					StdinData:   []byte(conf),
				}

				gomega.Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer ginkgo.GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					gomega.Expect(err).To(gomega.MatchError("unshapedSubnets and shapedSubnets cannot be both specified, one of them should be discarded"))
					return nil
				})).To(gomega.Succeed())
			})

			ginkgo.It(fmt.Sprintf("[%s] fails an invalid ingress config", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 0,
			"ingressBurst": 123,
			"egressRate": 123,
			"egressBurst": 123,
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      "eth0",
					StdinData:   []byte(conf),
				}

				gomega.Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer ginkgo.GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					gomega.Expect(err).To(gomega.MatchError("if burst is set, rate must also be set"))
					return nil
				})).To(gomega.Succeed())
			})

			ginkgo.It(fmt.Sprintf("[%s] fails an invalid egress config", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 123,
			"ingressBurst": 123,
			"egressRate": 0,
			"egressBurst": 123,
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      "eth0",
					StdinData:   []byte(conf),
				}

				gomega.Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer ginkgo.GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					gomega.Expect(err).To(gomega.MatchError("if burst is set, rate must also be set"))
					return nil
				})).To(gomega.Succeed())
			})

			// Runtime config parameters are expected to be preempted by the global config ones whenever specified
			ginkgo.It(fmt.Sprintf("[%s] should apply static config when both static config and runtime config exist", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 0,
			"ingressBurst": 0,
			"egressRate": 123,
			"egressBurst": 123,
			"unshapedSubnets": ["192.168.0.0/24"],
			"runtimeConfig": {
				"bandWidth": {
					"ingressRate": 8,
					"ingressBurst": 8,
					"egressRate": 16,
					"egressBurst": 9,
					"unshapedSubnets": ["10.0.0.0/8", "fd00:db8:abcd:1234:e000::/68"]
				}
			},
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      containerIfname,
					StdinData:   []byte(conf),
				}

				gomega.Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer ginkgo.GinkgoRecover()
					r, out, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(out))
					result, err := types100.GetResult(r)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					gomega.Expect(result.Interfaces).To(gomega.HaveLen(3))
					gomega.Expect(result.Interfaces[2].Name).To(gomega.Equal(ifbDeviceName))
					gomega.Expect(result.Interfaces[2].Sandbox).To(gomega.Equal(""))

					ifbLink, err := netlink.LinkByName(ifbDeviceName)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Expect(ifbLink.Attrs().MTU).To(gomega.Equal(hostIfaceMTU))

					qdiscs, err := netlink.QdiscList(ifbLink)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					gomega.Expect(qdiscs).To(gomega.HaveLen(1))
					gomega.Expect(qdiscs[0].Attrs().LinkIndex).To(gomega.Equal(ifbLink.Attrs().Index))
					gomega.Expect(qdiscs[0]).To(gomega.BeAssignableToTypeOf(&netlink.Htb{}))
					gomega.Expect(qdiscs[0].(*netlink.Htb).Defcls).To(gomega.Equal(uint32(ShapedClassMinorID)))

					classes, err := netlink.ClassList(ifbLink, qdiscs[0].Attrs().Handle)

					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Expect(classes).To(gomega.HaveLen(2))

					// Uncapped class
					gomega.Expect(classes[0]).To(gomega.BeAssignableToTypeOf(&netlink.HtbClass{}))
					gomega.Expect(classes[0].(*netlink.HtbClass).Handle).To(gomega.Equal(netlink.MakeHandle(1, 1)))
					gomega.Expect(classes[0].(*netlink.HtbClass).Rate).To(gomega.Equal(UncappedRate))
					gomega.Expect(classes[0].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(0)))
					gomega.Expect(classes[0].(*netlink.HtbClass).Ceil).To(gomega.Equal(UncappedRate))
					gomega.Expect(classes[0].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

					// Class with traffic shapping settings
					gomega.Expect(classes[1]).To(gomega.BeAssignableToTypeOf(&netlink.HtbClass{}))
					gomega.Expect(classes[1].(*netlink.HtbClass).Handle).To(gomega.Equal(netlink.MakeHandle(1, uint16(qdiscs[0].(*netlink.Htb).Defcls))))
					gomega.Expect(classes[1].(*netlink.HtbClass).Rate).To(gomega.Equal(uint64(15)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(7812500)))
					gomega.Expect(classes[1].(*netlink.HtbClass).Ceil).To(gomega.Equal(uint64(30)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

					filters, err := netlink.FilterList(ifbLink, qdiscs[0].Attrs().Handle)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Expect(filters).To(gomega.HaveLen(1))

					// traffic to 192.168.0.0/24 redirected to uncapped class
					gomega.Expect(filters[0]).To(gomega.BeAssignableToTypeOf(&netlink.U32{}))
					gomega.Expect(filters[0].(*netlink.U32).Actions).To(gomega.BeEmpty())
					gomega.Expect(filters[0].Attrs().Protocol).To(gomega.Equal(uint16(syscall.ETH_P_IP)))
					gomega.Expect(filters[0].Attrs().LinkIndex).To(gomega.Equal(ifbLink.Attrs().Index))
					gomega.Expect(filters[0].Attrs().Priority).To(gomega.Equal(uint16(16)))
					gomega.Expect(filters[0].Attrs().Parent).To(gomega.Equal(qdiscs[0].Attrs().Handle))
					gomega.Expect(filters[0].(*netlink.U32).ClassId).To(gomega.Equal(netlink.MakeHandle(1, 1)))

					filterSel := filters[0].(*netlink.U32).Sel
					gomega.Expect(filterSel).To(gomega.BeAssignableToTypeOf(&netlink.TcU32Sel{}))
					gomega.Expect(filterSel.Flags).To(gomega.Equal(uint8(netlink.TC_U32_TERMINAL)))
					gomega.Expect(filterSel.Keys).To(gomega.HaveLen(1))
					gomega.Expect(filterSel.Nkeys).To(gomega.Equal(uint8(1)))

					// The filter should match to 192.168.0.0/24 dst address in other words it should be:
					// match c0a80000/ffffff00 at 16
					selKey := filterSel.Keys[0]
					gomega.Expect(selKey.Val).To(gomega.Equal(uint32(192*math.Pow(256, 3) + 168*math.Pow(256, 2))))
					gomega.Expect(selKey.Off).To(gomega.Equal(int32(16)))
					gomega.Expect(selKey.Mask).To(gomega.Equal(uint32(255*math.Pow(256, 3) + 255*math.Pow(256, 2) + 255*256)))

					hostVethLink, err := netlink.LinkByName(hostIfname)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					qdiscFilters, err := netlink.FilterList(hostVethLink, netlink.MakeHandle(0xffff, 0))
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					gomega.Expect(qdiscFilters).To(gomega.HaveLen(1))
					gomega.Expect(qdiscFilters[0].(*netlink.U32).Actions[0].(*netlink.MirredAction).Ifindex).To(gomega.Equal(ifbLink.Attrs().Index))

					return nil
				})).To(gomega.Succeed())

				// Container ingress (host egress)
				gomega.Expect(hostNs.Do(func(n ns.NetNS) error {
					defer ginkgo.GinkgoRecover()

					vethLink, err := netlink.LinkByName(hostIfname)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					qdiscs, err := netlink.QdiscList(vethLink)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					// No ingress QoS just mirroring
					gomega.Expect(qdiscs).To(gomega.HaveLen(2))
					gomega.Expect(qdiscs[0].Attrs().LinkIndex).To(gomega.Equal(vethLink.Attrs().Index))
					gomega.Expect(qdiscs[0]).NotTo(gomega.BeAssignableToTypeOf(&netlink.Htb{}))
					gomega.Expect(qdiscs[1]).NotTo(gomega.BeAssignableToTypeOf(&netlink.Htb{}))

					return nil
				})).To(gomega.Succeed())
			})

			ginkgo.It(fmt.Sprintf("[%s] should apply static config when both static config and runtime config exist (bad config example)", ver), func() {
				conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 0,
			"ingressBurst": 123,
			"egressRate": 123,
			"egressBurst": 123,
			"runtimeConfig": {
				"bandWidth": {
					"ingressRate": 8,
					"ingressBurst": 8,
					"egressRate": 16,
					"egressBurst": 9
				}
			},
			"prevResult": {
				"interfaces": [
					{
						"name": "%s",
						"sandbox": ""
					},
					{
						"name": "%s",
						"sandbox": "%s"
					}
				],
				"ips": [
					{
						"version": "4",
						"address": "%s/24",
						"gateway": "10.0.0.1",
						"interface": 1
					}
				],
				"routes": []
			}
		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      "eth0",
					StdinData:   []byte(conf),
				}

				gomega.Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer ginkgo.GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					gomega.Expect(err).To(gomega.MatchError("if burst is set, rate must also be set"))
					return nil
				})).To(gomega.Succeed())
			})
		})
	}

	ginkgo.Describe("Validating input", func() {
		ginkgo.It("Should allow only 4GB burst rate", func() {
			err := validateRateAndBurst(5000, 4*1024*1024*1024*8-16) // 2 bytes less than the max should pass
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
			err = validateRateAndBurst(5000, 4*1024*1024*1024*8) // we're 1 bit above MaxUint32
			gomega.Expect(err).To(gomega.HaveOccurred())
			err = validateRateAndBurst(0, 1)
			gomega.Expect(err).To(gomega.HaveOccurred())
			err = validateRateAndBurst(1, 0)
			gomega.Expect(err).To(gomega.HaveOccurred())
			err = validateRateAndBurst(0, 0)
			gomega.Expect(err).NotTo(gomega.HaveOccurred())
		})

		ginkgo.It("Should fail if both ShapedSubnets and UnshapedSubnets are specified", func() {
			err := validateSubnets([]string{"10.0.0.0/8"}, []string{"192.168.0.0/24"})
			gomega.Expect(err).To(gomega.HaveOccurred())
		})

		ginkgo.It("Should fail if specified UnshapedSubnets are not valid CIDRs", func() {
			err := validateSubnets([]string{"10.0.0.0/8", "hello"}, []string{})
			gomega.Expect(err).To(gomega.HaveOccurred())
		})

		ginkgo.It("Should fail if specified ShapedSubnets are not valid CIDRs", func() {
			err := validateSubnets([]string{}, []string{"10.0.0.0/8", "hello"})
			gomega.Expect(err).To(gomega.HaveOccurred())
		})
	})
})
