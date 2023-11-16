// Copyright 2018 CNI authors
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

var _ = ginkgo.Describe("bandwidth test", func() {
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
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		ginkgo.Describe("cmdADD", func() {
			ginkgo.It(fmt.Sprintf("[%s] works with a Veth pair without any unbounded traffic", ver), func() {
				conf := fmt.Sprintf(`{
					"cniVersion": "%s",
					"name": "cni-plugin-bandwidth-test",
					"type": "bandwidth",
					"ingressRate": 8,
					"ingressBurst": 8,
					"egressRate": 16,
					"egressBurst": 12,
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

				// Container egress (host ingress)
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
					gomega.Expect(classes[1].(*netlink.HtbClass).Rate).To(gomega.Equal(uint64(2)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(7812500)))
					gomega.Expect(classes[1].(*netlink.HtbClass).Ceil).To(gomega.Equal(uint64(4)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

					// Since we do not exclude anything from egress traffic shapping, we should not find any filter
					filters, err := netlink.FilterList(ifbLink, qdiscs[0].Attrs().Handle)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Expect(filters).To(gomega.BeEmpty())

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

					gomega.Expect(qdiscs).To(gomega.HaveLen(2))
					gomega.Expect(qdiscs[0].Attrs().LinkIndex).To(gomega.Equal(vethLink.Attrs().Index))
					gomega.Expect(qdiscs[0]).To(gomega.BeAssignableToTypeOf(&netlink.Htb{}))
					gomega.Expect(qdiscs[0].(*netlink.Htb).Defcls).To(gomega.Equal(uint32(ShapedClassMinorID)))

					classes, err := netlink.ClassList(vethLink, qdiscs[0].Attrs().Handle)

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
					gomega.Expect(classes[1].(*netlink.HtbClass).Rate).To(gomega.Equal(uint64(1)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(15625000)))
					gomega.Expect(classes[1].(*netlink.HtbClass).Ceil).To(gomega.Equal(uint64(2)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

					// Since we do not exclude anything from ingress traffic shapping, we should not find any filter
					filters, err := netlink.FilterList(vethLink, qdiscs[0].Attrs().Handle)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Expect(filters).To(gomega.BeEmpty())
					return nil
				})).To(gomega.Succeed())
			})

			ginkgo.It(fmt.Sprintf("[%s] works with a Veth pair with some ipv4 and ipv6 unbounded traffic", ver), func() {
				conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "cni-plugin-bandwidth-test",
				"type": "bandwidth",
				"ingressRate": 8,
				"ingressBurst": 8,
				"egressRate": 16,
				"egressBurst": 12,
				"unshapedSubnets": [
					"10.0.0.0/8",
					"fd00:db8:abcd:1234:e000::/68"
				],
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

				// Container egress (host ingress)
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
					gomega.Expect(classes[1].(*netlink.HtbClass).Rate).To(gomega.Equal(uint64(2)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(7812500)))
					gomega.Expect(classes[1].(*netlink.HtbClass).Ceil).To(gomega.Equal(uint64(4)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

					filters, err := netlink.FilterList(ifbLink, qdiscs[0].Attrs().Handle)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Expect(filters).To(gomega.HaveLen(2))

					// traffic to fd00:db8:abcd:1234:e000::/68 redirected to uncapped class
					gomega.Expect(filters[0]).To(gomega.BeAssignableToTypeOf(&netlink.U32{}))
					gomega.Expect(filters[0].(*netlink.U32).Actions).To(gomega.BeEmpty())
					gomega.Expect(filters[0].Attrs().Protocol).To(gomega.Equal(uint16(syscall.ETH_P_IPV6)))
					gomega.Expect(filters[0].Attrs().LinkIndex).To(gomega.Equal(ifbLink.Attrs().Index))
					gomega.Expect(filters[0].Attrs().Priority).To(gomega.Equal(uint16(15)))
					gomega.Expect(filters[0].Attrs().Parent).To(gomega.Equal(qdiscs[0].Attrs().Handle))
					gomega.Expect(filters[0].(*netlink.U32).ClassId).To(gomega.Equal(netlink.MakeHandle(1, 1)))

					filterSel := filters[0].(*netlink.U32).Sel
					gomega.Expect(filterSel).To(gomega.BeAssignableToTypeOf(&netlink.TcU32Sel{}))
					gomega.Expect(filterSel.Flags).To(gomega.Equal(uint8(netlink.TC_U32_TERMINAL)))
					gomega.Expect(filterSel.Keys).To(gomega.HaveLen(3))
					gomega.Expect(filterSel.Nkeys).To(gomega.Equal(uint8(3)))

					// The filter should match to fd00:db8:abcd:1234:e000::/68 dst address in other words it should be:
					// match 0xfd000db8/0xffffffff at 24
					// match 0xabcd1234/0xffffffff at 28
					// match 0xe0000000/0xf0000000 at 32
					// (and last match discarded because it would be equivalent to a matchall/true condition at 36)
					gomega.Expect(filterSel.Keys[0].Off).To(gomega.Equal(int32(24)))
					gomega.Expect(filterSel.Keys[0].Val).To(gomega.Equal(uint32(4244639160)))
					gomega.Expect(filterSel.Keys[0].Mask).To(gomega.Equal(uint32(4294967295)))

					gomega.Expect(filterSel.Keys[1].Off).To(gomega.Equal(int32(28)))
					gomega.Expect(filterSel.Keys[1].Val).To(gomega.Equal(uint32(2882343476)))
					gomega.Expect(filterSel.Keys[1].Mask).To(gomega.Equal(uint32(4294967295)))

					gomega.Expect(filterSel.Keys[2].Off).To(gomega.Equal(int32(32)))
					gomega.Expect(filterSel.Keys[2].Val).To(gomega.Equal(uint32(3758096384)))
					gomega.Expect(filterSel.Keys[2].Mask).To(gomega.Equal(uint32(4026531840)))

					// traffic to 10.0.0.0/8 redirected to uncapped class
					gomega.Expect(filters[1]).To(gomega.BeAssignableToTypeOf(&netlink.U32{}))
					gomega.Expect(filters[1].(*netlink.U32).Actions).To(gomega.BeEmpty())
					gomega.Expect(filters[1].Attrs().Protocol).To(gomega.Equal(uint16(syscall.ETH_P_IP)))
					gomega.Expect(filters[1].Attrs().LinkIndex).To(gomega.Equal(ifbLink.Attrs().Index))
					gomega.Expect(filters[1].Attrs().Priority).To(gomega.Equal(uint16(16)))
					gomega.Expect(filters[1].Attrs().Parent).To(gomega.Equal(qdiscs[0].Attrs().Handle))
					gomega.Expect(filters[1].(*netlink.U32).ClassId).To(gomega.Equal(netlink.MakeHandle(1, 1)))

					filterSel = filters[1].(*netlink.U32).Sel
					gomega.Expect(filterSel).To(gomega.BeAssignableToTypeOf(&netlink.TcU32Sel{}))
					gomega.Expect(filterSel.Flags).To(gomega.Equal(uint8(netlink.TC_U32_TERMINAL)))
					gomega.Expect(filterSel.Keys).To(gomega.HaveLen(1))
					gomega.Expect(filterSel.Nkeys).To(gomega.Equal(uint8(1)))

					// The filter should match to 10.0.0.0/8 dst address in other words it should be:
					// match 0a000000/ff000000 at 16
					selKey := filterSel.Keys[0]
					gomega.Expect(selKey.Val).To(gomega.Equal(uint32(10 * math.Pow(256, 3))))
					gomega.Expect(selKey.Off).To(gomega.Equal(int32(16)))
					gomega.Expect(selKey.Mask).To(gomega.Equal(uint32(255 * math.Pow(256, 3))))

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

					gomega.Expect(qdiscs).To(gomega.HaveLen(2))
					gomega.Expect(qdiscs[0].Attrs().LinkIndex).To(gomega.Equal(vethLink.Attrs().Index))
					gomega.Expect(qdiscs[0]).To(gomega.BeAssignableToTypeOf(&netlink.Htb{}))
					gomega.Expect(qdiscs[0].(*netlink.Htb).Defcls).To(gomega.Equal(uint32(ShapedClassMinorID)))

					classes, err := netlink.ClassList(vethLink, qdiscs[0].Attrs().Handle)

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
					gomega.Expect(classes[1].(*netlink.HtbClass).Rate).To(gomega.Equal(uint64(1)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(15625000)))
					gomega.Expect(classes[1].(*netlink.HtbClass).Ceil).To(gomega.Equal(uint64(2)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

					filters, err := netlink.FilterList(vethLink, qdiscs[0].Attrs().Handle)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Expect(filters).To(gomega.HaveLen(2))

					// traffic to fd00:db8:abcd:1234:e000::/68 redirected to uncapped class
					gomega.Expect(filters[0]).To(gomega.BeAssignableToTypeOf(&netlink.U32{}))
					gomega.Expect(filters[0].(*netlink.U32).Actions).To(gomega.BeEmpty())
					gomega.Expect(filters[0].Attrs().Protocol).To(gomega.Equal(uint16(syscall.ETH_P_IPV6)))
					gomega.Expect(filters[0].Attrs().LinkIndex).To(gomega.Equal(vethLink.Attrs().Index))
					gomega.Expect(filters[0].Attrs().Priority).To(gomega.Equal(uint16(15)))
					gomega.Expect(filters[0].Attrs().Parent).To(gomega.Equal(qdiscs[0].Attrs().Handle))
					gomega.Expect(filters[0].(*netlink.U32).ClassId).To(gomega.Equal(netlink.MakeHandle(1, 1)))

					filterSel := filters[0].(*netlink.U32).Sel
					gomega.Expect(filterSel).To(gomega.BeAssignableToTypeOf(&netlink.TcU32Sel{}))
					gomega.Expect(filterSel.Flags).To(gomega.Equal(uint8(netlink.TC_U32_TERMINAL)))
					gomega.Expect(filterSel.Keys).To(gomega.HaveLen(3))
					gomega.Expect(filterSel.Nkeys).To(gomega.Equal(uint8(3)))

					// The filter should match to fd00:db8:abcd:1234:e000::/68 dst address in other words it should be:
					// match 0xfd000db8/0xffffffff at 24
					// match 0xabcd1234/0xffffffff at 28
					// match 0xe0000000/0xf0000000 at 32
					// (and last match discarded because it would be equivalent to a matchall/true condition at 36)
					gomega.Expect(filterSel.Keys[0].Off).To(gomega.Equal(int32(24)))
					gomega.Expect(filterSel.Keys[0].Val).To(gomega.Equal(uint32(4244639160)))
					gomega.Expect(filterSel.Keys[0].Mask).To(gomega.Equal(uint32(4294967295)))

					gomega.Expect(filterSel.Keys[1].Off).To(gomega.Equal(int32(28)))
					gomega.Expect(filterSel.Keys[1].Val).To(gomega.Equal(uint32(2882343476)))
					gomega.Expect(filterSel.Keys[1].Mask).To(gomega.Equal(uint32(4294967295)))

					gomega.Expect(filterSel.Keys[2].Off).To(gomega.Equal(int32(32)))
					gomega.Expect(filterSel.Keys[2].Val).To(gomega.Equal(uint32(3758096384)))
					gomega.Expect(filterSel.Keys[2].Mask).To(gomega.Equal(uint32(4026531840)))

					// traffic to 10.0.0.0/8 redirected to uncapped class
					gomega.Expect(filters[1]).To(gomega.BeAssignableToTypeOf(&netlink.U32{}))
					gomega.Expect(filters[1].(*netlink.U32).Actions).To(gomega.BeEmpty())
					gomega.Expect(filters[1].Attrs().Protocol).To(gomega.Equal(uint16(syscall.ETH_P_IP)))
					gomega.Expect(filters[1].Attrs().LinkIndex).To(gomega.Equal(vethLink.Attrs().Index))
					gomega.Expect(filters[1].Attrs().Priority).To(gomega.Equal(uint16(16)))
					gomega.Expect(filters[1].Attrs().Parent).To(gomega.Equal(qdiscs[0].Attrs().Handle))
					gomega.Expect(filters[1].(*netlink.U32).ClassId).To(gomega.Equal(netlink.MakeHandle(1, 1)))

					filterSel = filters[1].(*netlink.U32).Sel
					gomega.Expect(filterSel).To(gomega.BeAssignableToTypeOf(&netlink.TcU32Sel{}))
					gomega.Expect(filterSel.Flags).To(gomega.Equal(uint8(netlink.TC_U32_TERMINAL)))
					gomega.Expect(filterSel.Keys).To(gomega.HaveLen(1))
					gomega.Expect(filterSel.Nkeys).To(gomega.Equal(uint8(1)))

					// The filter should match to 10.0.0.0/8 dst address in other words it should be:
					// match 0a000000/ff000000 at 16
					selKey := filterSel.Keys[0]
					gomega.Expect(selKey.Val).To(gomega.Equal(uint32(10 * math.Pow(256, 3))))
					gomega.Expect(selKey.Off).To(gomega.Equal(int32(16)))
					gomega.Expect(selKey.Mask).To(gomega.Equal(uint32(255 * math.Pow(256, 3))))

					return nil
				})).To(gomega.Succeed())
			})
		})

		ginkgo.It(fmt.Sprintf("[%s] works with a Veth pair with some ipv4 and ipv6 shaped traffic for specific subnets", ver), func() {
			conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 8,
			"ingressBurst": 8,
			"egressRate": 16,
			"egressBurst": 12,
			"shapedSubnets": [
				"10.0.0.0/8",
				"fd00:db8:abcd:1234:e000::/68"
			],
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

			// Container egress (host ingress)
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
				gomega.Expect(qdiscs[0].(*netlink.Htb).Defcls).To(gomega.Equal(uint32(UnShapedClassMinorID)))

				classes, err := netlink.ClassList(ifbLink, qdiscs[0].Attrs().Handle)

				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(classes).To(gomega.HaveLen(2))

				// Uncapped class
				gomega.Expect(classes[0]).To(gomega.BeAssignableToTypeOf(&netlink.HtbClass{}))
				gomega.Expect(classes[0].(*netlink.HtbClass).Handle).To(gomega.Equal(netlink.MakeHandle(1, UnShapedClassMinorID)))
				gomega.Expect(classes[0].(*netlink.HtbClass).Rate).To(gomega.Equal(UncappedRate))
				gomega.Expect(classes[0].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(0)))
				gomega.Expect(classes[0].(*netlink.HtbClass).Ceil).To(gomega.Equal(UncappedRate))
				gomega.Expect(classes[0].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

				// Class with traffic shapping settings
				gomega.Expect(classes[1]).To(gomega.BeAssignableToTypeOf(&netlink.HtbClass{}))
				gomega.Expect(classes[1].(*netlink.HtbClass).Handle).To(gomega.Equal(netlink.MakeHandle(1, ShapedClassMinorID)))
				gomega.Expect(classes[1].(*netlink.HtbClass).Rate).To(gomega.Equal(uint64(2)))
				// gomega.Expect(classes[1].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(7812500)))
				gomega.Expect(classes[1].(*netlink.HtbClass).Ceil).To(gomega.Equal(uint64(4)))
				// gomega.Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

				filters, err := netlink.FilterList(ifbLink, qdiscs[0].Attrs().Handle)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(filters).To(gomega.HaveLen(2))

				// traffic to fd00:db8:abcd:1234:e000::/68 redirected to uncapped class
				gomega.Expect(filters[0]).To(gomega.BeAssignableToTypeOf(&netlink.U32{}))
				gomega.Expect(filters[0].(*netlink.U32).Actions).To(gomega.BeEmpty())
				gomega.Expect(filters[0].Attrs().Protocol).To(gomega.Equal(uint16(syscall.ETH_P_IPV6)))
				gomega.Expect(filters[0].Attrs().LinkIndex).To(gomega.Equal(ifbLink.Attrs().Index))
				gomega.Expect(filters[0].Attrs().Priority).To(gomega.Equal(uint16(15)))
				gomega.Expect(filters[0].Attrs().Parent).To(gomega.Equal(qdiscs[0].Attrs().Handle))
				gomega.Expect(filters[0].(*netlink.U32).ClassId).To(gomega.Equal(netlink.MakeHandle(1, ShapedClassMinorID)))

				filterSel := filters[0].(*netlink.U32).Sel
				gomega.Expect(filterSel).To(gomega.BeAssignableToTypeOf(&netlink.TcU32Sel{}))
				gomega.Expect(filterSel.Flags).To(gomega.Equal(uint8(netlink.TC_U32_TERMINAL)))
				gomega.Expect(filterSel.Keys).To(gomega.HaveLen(3))
				gomega.Expect(filterSel.Nkeys).To(gomega.Equal(uint8(3)))

				// The filter should match to fd00:db8:abcd:1234:e000::/68 dst address in other words it should be:
				// match 0xfd000db8/0xffffffff at 24
				// match 0xabcd1234/0xffffffff at 28
				// match 0xe0000000/0xf0000000 at 32
				// (and last match discarded because it would be equivalent to a matchall/true condition at 36)
				gomega.Expect(filterSel.Keys[0].Off).To(gomega.Equal(int32(24)))
				gomega.Expect(filterSel.Keys[0].Val).To(gomega.Equal(uint32(4244639160)))
				gomega.Expect(filterSel.Keys[0].Mask).To(gomega.Equal(uint32(4294967295)))

				gomega.Expect(filterSel.Keys[1].Off).To(gomega.Equal(int32(28)))
				gomega.Expect(filterSel.Keys[1].Val).To(gomega.Equal(uint32(2882343476)))
				gomega.Expect(filterSel.Keys[1].Mask).To(gomega.Equal(uint32(4294967295)))

				gomega.Expect(filterSel.Keys[2].Off).To(gomega.Equal(int32(32)))
				gomega.Expect(filterSel.Keys[2].Val).To(gomega.Equal(uint32(3758096384)))
				gomega.Expect(filterSel.Keys[2].Mask).To(gomega.Equal(uint32(4026531840)))

				// traffic to 10.0.0.0/8 redirected to uncapped class
				gomega.Expect(filters[1]).To(gomega.BeAssignableToTypeOf(&netlink.U32{}))
				gomega.Expect(filters[1].(*netlink.U32).Actions).To(gomega.BeEmpty())
				gomega.Expect(filters[1].Attrs().Protocol).To(gomega.Equal(uint16(syscall.ETH_P_IP)))
				gomega.Expect(filters[1].Attrs().LinkIndex).To(gomega.Equal(ifbLink.Attrs().Index))
				gomega.Expect(filters[1].Attrs().Priority).To(gomega.Equal(uint16(16)))
				gomega.Expect(filters[1].Attrs().Parent).To(gomega.Equal(qdiscs[0].Attrs().Handle))
				gomega.Expect(filters[1].(*netlink.U32).ClassId).To(gomega.Equal(netlink.MakeHandle(1, ShapedClassMinorID)))

				filterSel = filters[1].(*netlink.U32).Sel
				gomega.Expect(filterSel).To(gomega.BeAssignableToTypeOf(&netlink.TcU32Sel{}))
				gomega.Expect(filterSel.Flags).To(gomega.Equal(uint8(netlink.TC_U32_TERMINAL)))
				gomega.Expect(filterSel.Keys).To(gomega.HaveLen(1))
				gomega.Expect(filterSel.Nkeys).To(gomega.Equal(uint8(1)))

				// The filter should match to 10.0.0.0/8 dst address in other words it should be:
				// match 0a000000/ff000000 at 16
				selKey := filterSel.Keys[0]
				gomega.Expect(selKey.Val).To(gomega.Equal(uint32(10 * math.Pow(256, 3))))
				gomega.Expect(selKey.Off).To(gomega.Equal(int32(16)))
				gomega.Expect(selKey.Mask).To(gomega.Equal(uint32(255 * math.Pow(256, 3))))

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

				gomega.Expect(qdiscs).To(gomega.HaveLen(2))
				gomega.Expect(qdiscs[0].Attrs().LinkIndex).To(gomega.Equal(vethLink.Attrs().Index))
				gomega.Expect(qdiscs[0]).To(gomega.BeAssignableToTypeOf(&netlink.Htb{}))
				gomega.Expect(qdiscs[0].(*netlink.Htb).Defcls).To(gomega.Equal(uint32(UnShapedClassMinorID)))

				classes, err := netlink.ClassList(vethLink, qdiscs[0].Attrs().Handle)

				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(classes).To(gomega.HaveLen(2))

				// Uncapped class
				gomega.Expect(classes[0]).To(gomega.BeAssignableToTypeOf(&netlink.HtbClass{}))
				gomega.Expect(classes[0].(*netlink.HtbClass).Handle).To(gomega.Equal(netlink.MakeHandle(1, UnShapedClassMinorID)))
				gomega.Expect(classes[0].(*netlink.HtbClass).Rate).To(gomega.Equal(UncappedRate))
				gomega.Expect(classes[0].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(0)))
				gomega.Expect(classes[0].(*netlink.HtbClass).Ceil).To(gomega.Equal(UncappedRate))
				gomega.Expect(classes[0].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

				// Class with traffic shapping settings
				gomega.Expect(classes[1]).To(gomega.BeAssignableToTypeOf(&netlink.HtbClass{}))
				gomega.Expect(classes[1].(*netlink.HtbClass).Handle).To(gomega.Equal(netlink.MakeHandle(1, ShapedClassMinorID)))
				gomega.Expect(classes[1].(*netlink.HtbClass).Rate).To(gomega.Equal(uint64(1)))
				// gomega.Expect(classes[1].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(15625000)))
				gomega.Expect(classes[1].(*netlink.HtbClass).Ceil).To(gomega.Equal(uint64(2)))
				// gomega.Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

				filters, err := netlink.FilterList(vethLink, qdiscs[0].Attrs().Handle)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(filters).To(gomega.HaveLen(2))

				// traffic to fd00:db8:abcd:1234:e000::/68 redirected to uncapped class
				gomega.Expect(filters[0]).To(gomega.BeAssignableToTypeOf(&netlink.U32{}))
				gomega.Expect(filters[0].(*netlink.U32).Actions).To(gomega.BeEmpty())
				gomega.Expect(filters[0].Attrs().Protocol).To(gomega.Equal(uint16(syscall.ETH_P_IPV6)))
				gomega.Expect(filters[0].Attrs().LinkIndex).To(gomega.Equal(vethLink.Attrs().Index))
				gomega.Expect(filters[0].Attrs().Priority).To(gomega.Equal(uint16(15)))
				gomega.Expect(filters[0].Attrs().Parent).To(gomega.Equal(qdiscs[0].Attrs().Handle))
				gomega.Expect(filters[0].(*netlink.U32).ClassId).To(gomega.Equal(netlink.MakeHandle(1, ShapedClassMinorID)))

				filterSel := filters[0].(*netlink.U32).Sel
				gomega.Expect(filterSel).To(gomega.BeAssignableToTypeOf(&netlink.TcU32Sel{}))
				gomega.Expect(filterSel.Flags).To(gomega.Equal(uint8(netlink.TC_U32_TERMINAL)))
				gomega.Expect(filterSel.Keys).To(gomega.HaveLen(3))
				gomega.Expect(filterSel.Nkeys).To(gomega.Equal(uint8(3)))

				// The filter should match to fd00:db8:abcd:1234:e000::/68 dst address in other words it should be:
				// match 0xfd000db8/0xffffffff at 24
				// match 0xabcd1234/0xffffffff at 28
				// match 0xe0000000/0xf0000000 at 32
				// (and last match discarded because it would be equivalent to a matchall/true condition at 36)
				gomega.Expect(filterSel.Keys[0].Off).To(gomega.Equal(int32(24)))
				gomega.Expect(filterSel.Keys[0].Val).To(gomega.Equal(uint32(4244639160)))
				gomega.Expect(filterSel.Keys[0].Mask).To(gomega.Equal(uint32(4294967295)))

				gomega.Expect(filterSel.Keys[1].Off).To(gomega.Equal(int32(28)))
				gomega.Expect(filterSel.Keys[1].Val).To(gomega.Equal(uint32(2882343476)))
				gomega.Expect(filterSel.Keys[1].Mask).To(gomega.Equal(uint32(4294967295)))

				gomega.Expect(filterSel.Keys[2].Off).To(gomega.Equal(int32(32)))
				gomega.Expect(filterSel.Keys[2].Val).To(gomega.Equal(uint32(3758096384)))
				gomega.Expect(filterSel.Keys[2].Mask).To(gomega.Equal(uint32(4026531840)))

				// traffic to 10.0.0.0/8 redirected to uncapped class
				gomega.Expect(filters[1]).To(gomega.BeAssignableToTypeOf(&netlink.U32{}))
				gomega.Expect(filters[1].(*netlink.U32).Actions).To(gomega.BeEmpty())
				gomega.Expect(filters[1].Attrs().Protocol).To(gomega.Equal(uint16(syscall.ETH_P_IP)))
				gomega.Expect(filters[1].Attrs().LinkIndex).To(gomega.Equal(vethLink.Attrs().Index))
				gomega.Expect(filters[1].Attrs().Priority).To(gomega.Equal(uint16(16)))
				gomega.Expect(filters[1].Attrs().Parent).To(gomega.Equal(qdiscs[0].Attrs().Handle))
				gomega.Expect(filters[1].(*netlink.U32).ClassId).To(gomega.Equal(netlink.MakeHandle(1, ShapedClassMinorID)))

				filterSel = filters[1].(*netlink.U32).Sel
				gomega.Expect(filterSel).To(gomega.BeAssignableToTypeOf(&netlink.TcU32Sel{}))
				gomega.Expect(filterSel.Flags).To(gomega.Equal(uint8(netlink.TC_U32_TERMINAL)))
				gomega.Expect(filterSel.Keys).To(gomega.HaveLen(1))
				gomega.Expect(filterSel.Nkeys).To(gomega.Equal(uint8(1)))

				// The filter should match to 10.0.0.0/8 dst address in other words it should be:
				// match 0a000000/ff000000 at 16
				selKey := filterSel.Keys[0]
				gomega.Expect(selKey.Val).To(gomega.Equal(uint32(10 * math.Pow(256, 3))))
				gomega.Expect(selKey.Off).To(gomega.Equal(int32(16)))
				gomega.Expect(selKey.Mask).To(gomega.Equal(uint32(255 * math.Pow(256, 3))))

				return nil
			})).To(gomega.Succeed())
		})

		ginkgo.It(fmt.Sprintf("[%s] does not apply ingress when disabled", ver), func() {
			conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"ingressRate": 0,
			"ingressBurst": 0,
			"egressRate": 8000,
			"egressBurst": 80,
			"unshapedSubnets": [
					"10.0.0.0/8",
					"fd00:db8:abcd:1234:e000::/68"
			],
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

			// check container egress side / host ingress side, we expect to get some QoS setup there
			gomega.Expect(hostNs.Do(func(netNS ns.NetNS) error {
				defer ginkgo.GinkgoRecover()

				_, out, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, ifbDeviceName, []byte(conf), func() error { return cmdAdd(args) })
				gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(out))

				ifbLink, err := netlink.LinkByName(ifbDeviceName)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

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
				gomega.Expect(classes[1].(*netlink.HtbClass).Handle).To(gomega.Equal(netlink.MakeHandle(1, ShapedClassMinorID)))
				gomega.Expect(classes[1].(*netlink.HtbClass).Rate).To(gomega.Equal(uint64(1000)))
				// gomega.Expect(classes[1].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(7812500)))
				gomega.Expect(classes[1].(*netlink.HtbClass).Ceil).To(gomega.Equal(uint64(2000)))
				// gomega.Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

				filters, err := netlink.FilterList(ifbLink, qdiscs[0].Attrs().Handle)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(filters).To(gomega.HaveLen(2))

				// traffic to fd00:db8:abcd:1234:e000::/68 redirected to uncapped class
				gomega.Expect(filters[0]).To(gomega.BeAssignableToTypeOf(&netlink.U32{}))
				gomega.Expect(filters[0].(*netlink.U32).Actions).To(gomega.BeEmpty())
				gomega.Expect(filters[0].Attrs().Protocol).To(gomega.Equal(uint16(syscall.ETH_P_IPV6)))
				gomega.Expect(filters[0].Attrs().LinkIndex).To(gomega.Equal(ifbLink.Attrs().Index))
				gomega.Expect(filters[0].Attrs().Priority).To(gomega.Equal(uint16(15)))
				gomega.Expect(filters[0].Attrs().Parent).To(gomega.Equal(qdiscs[0].Attrs().Handle))
				gomega.Expect(filters[0].(*netlink.U32).ClassId).To(gomega.Equal(netlink.MakeHandle(1, 1)))

				filterSel := filters[0].(*netlink.U32).Sel
				gomega.Expect(filterSel).To(gomega.BeAssignableToTypeOf(&netlink.TcU32Sel{}))
				gomega.Expect(filterSel.Flags).To(gomega.Equal(uint8(netlink.TC_U32_TERMINAL)))
				gomega.Expect(filterSel.Keys).To(gomega.HaveLen(3))
				gomega.Expect(filterSel.Nkeys).To(gomega.Equal(uint8(3)))

				// The filter should match to fd00:db8:abcd:1234:e000::/68 dst address in other words it should be:
				// match 0xfd000db8/0xffffffff at 24
				// match 0xabcd1234/0xffffffff at 28
				// match 0xe0000000/0xf0000000 at 32
				// (and last match discarded because it would be equivalent to a matchall/true condition at 36)
				gomega.Expect(filterSel.Keys[0].Off).To(gomega.Equal(int32(24)))
				gomega.Expect(filterSel.Keys[0].Val).To(gomega.Equal(uint32(4244639160)))
				gomega.Expect(filterSel.Keys[0].Mask).To(gomega.Equal(uint32(4294967295)))

				gomega.Expect(filterSel.Keys[1].Off).To(gomega.Equal(int32(28)))
				gomega.Expect(filterSel.Keys[1].Val).To(gomega.Equal(uint32(2882343476)))
				gomega.Expect(filterSel.Keys[1].Mask).To(gomega.Equal(uint32(4294967295)))

				gomega.Expect(filterSel.Keys[2].Off).To(gomega.Equal(int32(32)))
				gomega.Expect(filterSel.Keys[2].Val).To(gomega.Equal(uint32(3758096384)))
				gomega.Expect(filterSel.Keys[2].Mask).To(gomega.Equal(uint32(4026531840)))

				// traffic to 10.0.0.0/8 redirected to uncapped class
				gomega.Expect(filters[1]).To(gomega.BeAssignableToTypeOf(&netlink.U32{}))
				gomega.Expect(filters[1].(*netlink.U32).Actions).To(gomega.BeEmpty())
				gomega.Expect(filters[1].Attrs().Protocol).To(gomega.Equal(uint16(syscall.ETH_P_IP)))
				gomega.Expect(filters[1].Attrs().LinkIndex).To(gomega.Equal(ifbLink.Attrs().Index))
				gomega.Expect(filters[1].Attrs().Priority).To(gomega.Equal(uint16(16)))
				gomega.Expect(filters[1].Attrs().Parent).To(gomega.Equal(qdiscs[0].Attrs().Handle))
				gomega.Expect(filters[1].(*netlink.U32).ClassId).To(gomega.Equal(netlink.MakeHandle(1, 1)))

				filterSel = filters[1].(*netlink.U32).Sel
				gomega.Expect(filterSel).To(gomega.BeAssignableToTypeOf(&netlink.TcU32Sel{}))
				gomega.Expect(filterSel.Flags).To(gomega.Equal(uint8(netlink.TC_U32_TERMINAL)))
				gomega.Expect(filterSel.Keys).To(gomega.HaveLen(1))
				gomega.Expect(filterSel.Nkeys).To(gomega.Equal(uint8(1)))

				// The filter should match to 10.0.0.0/8 dst address in other words it should be:
				// match 0a000000/ff000000 at 16
				selKey := filterSel.Keys[0]
				gomega.Expect(selKey.Val).To(gomega.Equal(uint32(10 * math.Pow(256, 3))))
				gomega.Expect(selKey.Off).To(gomega.Equal(int32(16)))
				gomega.Expect(selKey.Mask).To(gomega.Equal(uint32(255 * math.Pow(256, 3))))

				// check traffic mirroring from veth to ifb
				hostVethLink, err := netlink.LinkByName(hostIfname)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				qdiscFilters, err := netlink.FilterList(hostVethLink, netlink.MakeHandle(0xffff, 0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Expect(qdiscFilters).To(gomega.HaveLen(1))
				gomega.Expect(qdiscFilters[0].(*netlink.U32).Actions[0].(*netlink.MirredAction).Ifindex).To(gomega.Equal(ifbLink.Attrs().Index))

				return nil
			})).To(gomega.Succeed())

			// check container ingress side / host egress side, we should not have any htb qdisc/classes/filters defined for the host veth
			// only the qdisc ingress + a noqueue qdisc
			gomega.Expect(hostNs.Do(func(n ns.NetNS) error {
				defer ginkgo.GinkgoRecover()

				containerIfLink, err := netlink.LinkByName(hostIfname)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				qdiscs, err := netlink.QdiscList(containerIfLink)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Expect(qdiscs).To(gomega.HaveLen(2))
				gomega.Expect(qdiscs[0]).NotTo(gomega.BeAssignableToTypeOf(&netlink.Htb{}))
				gomega.Expect(qdiscs[1]).NotTo(gomega.BeAssignableToTypeOf(&netlink.Htb{}))

				return nil
			})).To(gomega.Succeed())
		})

		ginkgo.It(fmt.Sprintf("[%s] does not apply egress when disabled", ver), func() {
			conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "cni-plugin-bandwidth-test",
				"type": "bandwidth",
				"egressRate": 0,
				"egressBurst": 0,
				"ingressRate": 8000,
				"ingressBurst": 80,
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

				_, out, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, ifbDeviceName, []byte(conf), func() error { return cmdAdd(args) })
				gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(out))

				// Since we do not setup any egress QoS, no ifb interface should be created at all
				_, err = netlink.LinkByName(ifbDeviceName)
				gomega.Expect(err).To(gomega.HaveOccurred())

				return nil
			})).To(gomega.Succeed())

			gomega.Expect(hostNs.Do(func(n ns.NetNS) error {
				defer ginkgo.GinkgoRecover()

				containerIfLink, err := netlink.LinkByName(hostIfname)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				// Only one qdisc should be found this time, no ingress qdisc should be there
				qdiscs, err := netlink.QdiscList(containerIfLink)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())

				gomega.Expect(qdiscs).To(gomega.HaveLen(1))
				gomega.Expect(qdiscs[0].Attrs().LinkIndex).To(gomega.Equal(containerIfLink.Attrs().Index))
				gomega.Expect(qdiscs[0]).To(gomega.BeAssignableToTypeOf(&netlink.Htb{}))
				gomega.Expect(qdiscs[0].(*netlink.Htb).Defcls).To(gomega.Equal(uint32(ShapedClassMinorID)))

				classes, err := netlink.ClassList(containerIfLink, qdiscs[0].Attrs().Handle)

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
				gomega.Expect(classes[1].(*netlink.HtbClass).Rate).To(gomega.Equal(uint64(1000)))
				// gomega.Expect(classes[1].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(15625000)))
				gomega.Expect(classes[1].(*netlink.HtbClass).Ceil).To(gomega.Equal(uint64(2000)))
				// gomega.Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

				// No subnets are exluded in this example so we should not get any filter
				filters, err := netlink.FilterList(containerIfLink, qdiscs[0].Attrs().Handle)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(filters).To(gomega.BeEmpty())

				// Just check no mirroring is setup
				qdiscFilters, err := netlink.FilterList(containerIfLink, netlink.MakeHandle(0xffff, 0))
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(qdiscFilters).To(gomega.BeEmpty())
				return nil
			})).To(gomega.Succeed())
		})

		ginkgo.It(fmt.Sprintf("[%s] works with a Veth pair using runtime config", ver), func() {
			conf := fmt.Sprintf(`{
			"cniVersion": "%s",
			"name": "cni-plugin-bandwidth-test",
			"type": "bandwidth",
			"runtimeConfig": {
				"bandWidth": {
					"ingressRate": 8,
					"ingressBurst": 8,
					"egressRate": 16,
					"egressBurst": 9,
					"unshapedSubnets": ["192.168.0.0/24"]
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
				gomega.Expect(classes[1].(*netlink.HtbClass).Rate).To(gomega.Equal(uint64(2)))
				// gomega.Expect(classes[1].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(7812500)))
				gomega.Expect(classes[1].(*netlink.HtbClass).Ceil).To(gomega.Equal(uint64(4)))
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

				gomega.Expect(qdiscs).To(gomega.HaveLen(2))
				gomega.Expect(qdiscs[0].Attrs().LinkIndex).To(gomega.Equal(vethLink.Attrs().Index))
				gomega.Expect(qdiscs[0]).To(gomega.BeAssignableToTypeOf(&netlink.Htb{}))
				gomega.Expect(qdiscs[0].(*netlink.Htb).Defcls).To(gomega.Equal(uint32(ShapedClassMinorID)))

				classes, err := netlink.ClassList(vethLink, qdiscs[0].Attrs().Handle)

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
				gomega.Expect(classes[1].(*netlink.HtbClass).Rate).To(gomega.Equal(uint64(1)))
				// gomega.Expect(classes[1].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(15625000)))
				gomega.Expect(classes[1].(*netlink.HtbClass).Ceil).To(gomega.Equal(uint64(2)))
				// gomega.Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

				filters, err := netlink.FilterList(vethLink, qdiscs[0].Attrs().Handle)
				gomega.Expect(err).NotTo(gomega.HaveOccurred())
				gomega.Expect(filters).To(gomega.HaveLen(1))

				// traffic to 192.168.0.0/24 redirected to uncapped class
				gomega.Expect(filters[0]).To(gomega.BeAssignableToTypeOf(&netlink.U32{}))
				gomega.Expect(filters[0].(*netlink.U32).Actions).To(gomega.BeEmpty())
				gomega.Expect(filters[0].Attrs().Protocol).To(gomega.Equal(uint16(syscall.ETH_P_IP)))
				gomega.Expect(filters[0].Attrs().LinkIndex).To(gomega.Equal(vethLink.Attrs().Index))
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
				return nil
			})).To(gomega.Succeed())
		})

		ginkgo.Describe("cmdDEL", func() {
			ginkgo.It(fmt.Sprintf("[%s] works with a Veth pair using 0.3.0 config", ver), func() {
				conf := fmt.Sprintf(`{
					"cniVersion": "%s",
					"name": "cni-plugin-bandwidth-test",
					"type": "bandwidth",
					"ingressRate": 8,
					"ingressBurst": 8,
					"egressRate": 9,
					"egressBurst": 9,
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
					_, out, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(out))

					_, err = netlink.LinkByName(hostIfname)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					_, err = netlink.LinkByName(ifbDeviceName)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					err = testutils.CmdDel(containerNs.Path(), args.ContainerID, "", func() error { return cmdDel(args) })
					gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(out))

					_, err = netlink.LinkByName(ifbDeviceName)
					gomega.Expect(err).To(gomega.HaveOccurred())

					// The host veth peer should remain as it has not be created by this plugin
					_, err = netlink.LinkByName(hostIfname)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					return nil
				})).To(gomega.Succeed())
			})
		})

		ginkgo.Describe("cmdCHECK", func() {
			ginkgo.It(fmt.Sprintf("[%s] works with a Veth pair", ver), func() {
				conf := fmt.Sprintf(`{
					"cniVersion": "%s",
					"name": "cni-plugin-bandwidth-test",
					"type": "bandwidth",
					"ingressRate": 8,
					"ingressBurst": 8,
					"egressRate": 9,
					"egressBurst": 9,
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
					_, out, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(out))

					_, err = netlink.LinkByName(hostIfname)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					_, err = netlink.LinkByName(ifbDeviceName)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					if testutils.SpecVersionHasCHECK(ver) {
						// Do CNI Check

						err = testutils.CmdCheck(containerNs.Path(), args.ContainerID, "", func() error { return cmdCheck(args) })
						gomega.Expect(err).NotTo(gomega.HaveOccurred())
					}

					err = testutils.CmdDel(containerNs.Path(), args.ContainerID, "", func() error { return cmdDel(args) })
					gomega.Expect(err).NotTo(gomega.HaveOccurred(), string(out))

					_, err = netlink.LinkByName(ifbDeviceName)
					gomega.Expect(err).To(gomega.HaveOccurred())

					// The host veth peer should remain as it has not be created by this plugin
					_, err = netlink.LinkByName(hostIfname)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					return nil
				})).To(gomega.Succeed())
			})
		})

		ginkgo.Describe("Getting the host interface which plugin should work on from veth peer of container interface", func() {
			ginkgo.It(fmt.Sprintf("[%s] should work with multiple host veth interfaces", ver), func() {
				// create veth peer in host ns
				vethName, peerName := "host-veth-peer1", "host-veth-peer2"
				createVethInOneNs(hostNs, vethName, peerName)

				conf := fmt.Sprintf(`{
					"cniVersion": "%s",
					"name": "cni-plugin-bandwidth-test",
					"type": "bandwidth",
					"ingressRate": 8,
					"ingressBurst": 8,
					"egressRate": 16,
					"egressBurst": 8,
					"prevResult": {
						"interfaces": [
							{
								"name": "%s",
								"sandbox": ""
							},
							{
								"name": "%s",
								"sandbox": ""
							},
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
				}`, ver, vethName, peerName, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

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

					gomega.Expect(result.Interfaces).To(gomega.HaveLen(5))
					gomega.Expect(result.Interfaces[4].Name).To(gomega.Equal(ifbDeviceName))
					gomega.Expect(result.Interfaces[4].Sandbox).To(gomega.Equal(""))

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
					gomega.Expect(classes[1].(*netlink.HtbClass).Rate).To(gomega.Equal(uint64(2)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(7812500)))
					gomega.Expect(classes[1].(*netlink.HtbClass).Ceil).To(gomega.Equal(uint64(4)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

					// Since we do not exclude anything from egress traffic shapping, we should not find any filter
					filters, err := netlink.FilterList(ifbLink, qdiscs[0].Attrs().Handle)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Expect(filters).To(gomega.BeEmpty())

					hostVethLink, err := netlink.LinkByName(hostIfname)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					qdiscFilters, err := netlink.FilterList(hostVethLink, netlink.MakeHandle(0xffff, 0))
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					gomega.Expect(qdiscFilters).To(gomega.HaveLen(1))
					gomega.Expect(qdiscFilters[0].(*netlink.U32).Actions[0].(*netlink.MirredAction).Ifindex).To(gomega.Equal(ifbLink.Attrs().Index))

					return nil
				})).To(gomega.Succeed())

				gomega.Expect(hostNs.Do(func(n ns.NetNS) error {
					defer ginkgo.GinkgoRecover()

					vethLink, err := netlink.LinkByName(hostIfname)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					qdiscs, err := netlink.QdiscList(vethLink)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())

					gomega.Expect(qdiscs).To(gomega.HaveLen(2))
					gomega.Expect(qdiscs[0].Attrs().LinkIndex).To(gomega.Equal(vethLink.Attrs().Index))
					gomega.Expect(qdiscs[0]).To(gomega.BeAssignableToTypeOf(&netlink.Htb{}))
					gomega.Expect(qdiscs[0].(*netlink.Htb).Defcls).To(gomega.Equal(uint32(ShapedClassMinorID)))

					classes, err := netlink.ClassList(vethLink, qdiscs[0].Attrs().Handle)

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
					gomega.Expect(classes[1].(*netlink.HtbClass).Rate).To(gomega.Equal(uint64(1)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Buffer).To(gomega.Equal(uint32(15625000)))
					gomega.Expect(classes[1].(*netlink.HtbClass).Ceil).To(gomega.Equal(uint64(2)))
					// gomega.Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(gomega.Equal(uint32(0)))

					// Since we do not exclude anything from ingress traffic shapping, we should not find any filter
					filters, err := netlink.FilterList(vethLink, qdiscs[0].Attrs().Handle)
					gomega.Expect(err).NotTo(gomega.HaveOccurred())
					gomega.Expect(filters).To(gomega.BeEmpty())

					return nil
				})).To(gomega.Succeed())
			})

			ginkgo.It(fmt.Sprintf("[%s] should fail when container interface has no veth peer", ver), func() {
				// create a macvlan device to be container interface
				macvlanContainerIfname := "container-macv"
				createMacvlan(containerNs, containerIfname, macvlanContainerIfname)

				conf := fmt.Sprintf(`{
					"cniVersion": "%s",
					"name": "cni-plugin-bandwidth-test",
					"type": "bandwidth",
					"ingressRate": 8,
					"ingressBurst": 8,
					"egressRate": 16,
					"egressBurst": 8,
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
				}`, ver, hostIfname, macvlanContainerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      macvlanContainerIfname,
					StdinData:   []byte(conf),
				}

				gomega.Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer ginkgo.GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					gomega.Expect(err).To(gomega.HaveOccurred())

					return nil
				})).To(gomega.Succeed())
			})

			ginkgo.It(fmt.Sprintf("[%s] should fail when preResult has no interfaces", ver), func() {
				conf := fmt.Sprintf(`{
					"cniVersion": "%s",
					"name": "cni-plugin-bandwidth-test",
					"type": "bandwidth",
					"ingressRate": 8,
					"ingressBurst": 8,
					"egressRate": 16,
					"egressBurst": 8,
					"prevResult": {
						"interfaces": [],
						"ips": [],
						"routes": []
					}
				}`, ver)

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      "eth0",
					StdinData:   []byte(conf),
				}

				gomega.Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer ginkgo.GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					gomega.Expect(err).To(gomega.HaveOccurred())

					return nil
				})).To(gomega.Succeed())
			})

			ginkgo.It(fmt.Sprintf("[%s] should fail when veth peer of container interface does not match any of host interfaces in preResult", ver), func() {
				// fake a non-exist host interface name
				fakeHostIfname := fmt.Sprintf("%s-fake", hostIfname)

				conf := fmt.Sprintf(`{
					"cniVersion": "%s",
					"name": "cni-plugin-bandwidth-test",
					"type": "bandwidth",
					"ingressRate": 8,
					"ingressBurst": 8,
					"egressRate": 16,
					"egressBurst": 8,
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
				}`, ver, fakeHostIfname, containerIfname, containerNs.Path(), containerIP.String())

				args := &skel.CmdArgs{
					ContainerID: "dummy",
					Netns:       containerNs.Path(),
					IfName:      containerIfname,
					StdinData:   []byte(conf),
				}

				gomega.Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer ginkgo.GinkgoRecover()

					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					gomega.Expect(err).To(gomega.HaveOccurred())

					return nil
				})).To(gomega.Succeed())
			})
		})
	}
})
