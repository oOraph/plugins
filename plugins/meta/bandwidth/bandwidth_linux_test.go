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
	"encoding/json"
	"fmt"
	"math"
	"net"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types100 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
)

func buildOneConfig(name, cniVersion string, orig *PluginConf, prevResult types.Result) ([]byte, error) {
	var err error

	inject := map[string]interface{}{
		"name":       name,
		"cniVersion": cniVersion,
	}
	// Add previous plugin result
	if prevResult != nil {
		r, err := prevResult.GetAsVersion(cniVersion)
		Expect(err).NotTo(HaveOccurred())
		inject["prevResult"] = r
	}

	// Ensure every config uses the same name and version
	config := make(map[string]interface{})

	confBytes, err := json.Marshal(orig)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(confBytes, &config)
	if err != nil {
		return nil, fmt.Errorf("unmarshal existing network bytes: %s", err)
	}

	for key, value := range inject {
		config[key] = value
	}

	newBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	conf := &PluginConf{}
	if err := json.Unmarshal(newBytes, &conf); err != nil {
		return nil, fmt.Errorf("error parsing configuration: %s", err)
	}

	return newBytes, nil
}

var _ = Describe("bandwidth test", func() {
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

	BeforeEach(func() {
		var err error

		hostIfname = "host-veth"
		containerIfname = "container-veth"

		hostNs, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		containerNs, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		hostIP = net.IP{169, 254, 0, 1}
		containerIP = net.IP{10, 254, 0, 1}
		hostIfaceMTU = 1024
		ifbDeviceName = "bwpa8eda89404b7"

		createVeth(hostNs, hostIfname, containerNs, containerIfname, hostIP, containerIP, hostIfaceMTU)
	})

	AfterEach(func() {
		Expect(containerNs.Close()).To(Succeed())
		Expect(testutils.UnmountNS(containerNs)).To(Succeed())
		Expect(hostNs.Close()).To(Succeed())
		Expect(testutils.UnmountNS(hostNs)).To(Succeed())
	})

	// Bandwidth requires host-side interface info, and thus only
	// supports 0.3.0 and later CNI versions
	for _, ver := range []string{"0.3.0", "0.3.1", "0.4.0", "1.0.0"} {
		// Redefine ver inside for scope so real value is picked up by each dynamically defined It()
		// See Gingkgo's "Patterns for dynamically generating tests" documentation.
		ver := ver

		Describe("cmdADD", func() {
			It(fmt.Sprintf("[%s] works with a Veth pair wihtout any unbounded traffic", ver), func() {
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
				Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer GinkgoRecover()
					r, out, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					Expect(err).NotTo(HaveOccurred(), string(out))
					result, err := types100.GetResult(r)
					Expect(err).NotTo(HaveOccurred())

					Expect(result.Interfaces).To(HaveLen(3))
					Expect(result.Interfaces[2].Name).To(Equal(ifbDeviceName))
					Expect(result.Interfaces[2].Sandbox).To(Equal(""))

					ifbLink, err := netlink.LinkByName(ifbDeviceName)
					Expect(err).NotTo(HaveOccurred())
					Expect(ifbLink.Attrs().MTU).To(Equal(hostIfaceMTU))

					qdiscs, err := netlink.QdiscList(ifbLink)
					Expect(err).NotTo(HaveOccurred())

					Expect(qdiscs).To(HaveLen(1))
					Expect(qdiscs[0].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))

					Expect(qdiscs[0]).To(BeAssignableToTypeOf(&netlink.Htb{}))

					classes, err := netlink.ClassList(ifbLink, qdiscs[0].Attrs().Handle)

					Expect(err).NotTo(HaveOccurred())
					Expect(classes).To(HaveLen(2))

					// Uncapped class
					Expect(classes[0]).To(BeAssignableToTypeOf(&netlink.HtbClass{}))
					Expect(classes[0].(*netlink.HtbClass).Handle).To(Equal(netlink.MakeHandle(1, 1)))
					Expect(classes[0].(*netlink.HtbClass).Rate).To(Equal(uint64(UncappedRate)))
					Expect(classes[0].(*netlink.HtbClass).Buffer).To(Equal(uint32(0)))
					Expect(classes[0].(*netlink.HtbClass).Ceil).To(Equal(uint64(UncappedRate)))
					Expect(classes[0].(*netlink.HtbClass).Cbuffer).To(Equal(uint32(0)))

					// Class with traffic shapping settings
					Expect(classes[1]).To(BeAssignableToTypeOf(&netlink.HtbClass{}))
					Expect(classes[1].(*netlink.HtbClass).Handle).To(Equal(netlink.MakeHandle(1, uint16(qdiscs[0].(*netlink.Htb).Defcls))))
					Expect(classes[1].(*netlink.HtbClass).Rate).To(Equal(uint64(2)))
					// Expect(classes[1].(*netlink.HtbClass).Buffer).To(Equal(uint32(7812500)))
					Expect(classes[1].(*netlink.HtbClass).Ceil).To(Equal(uint64(4)))
					Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(Equal(uint32(0)))

					// Since we do not exclude anything from egress traffic shapping, we should not find any filter
					filters, err := netlink.FilterList(ifbLink, qdiscs[0].Attrs().Handle)
					Expect(err).NotTo(HaveOccurred())
					Expect(filters).To(HaveLen(0))

					hostVethLink, err := netlink.LinkByName(hostIfname)
					Expect(err).NotTo(HaveOccurred())

					qdiscFilters, err := netlink.FilterList(hostVethLink, netlink.MakeHandle(0xffff, 0))
					Expect(err).NotTo(HaveOccurred())

					Expect(qdiscFilters).To(HaveLen(1))
					Expect(qdiscFilters[0].(*netlink.U32).Actions[0].(*netlink.MirredAction).Ifindex).To(Equal(ifbLink.Attrs().Index))

					return nil
				})).To(Succeed())

				// Container ingress (host egress)
				Expect(hostNs.Do(func(n ns.NetNS) error {
					defer GinkgoRecover()

					ifbLink, err := netlink.LinkByName(hostIfname)
					Expect(err).NotTo(HaveOccurred())

					qdiscs, err := netlink.QdiscList(ifbLink)
					Expect(err).NotTo(HaveOccurred())

					Expect(qdiscs).To(HaveLen(2))
					Expect(qdiscs[0].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))

					Expect(qdiscs[0]).To(BeAssignableToTypeOf(&netlink.Htb{}))
					Expect(qdiscs[0].(*netlink.Htb).Defcls).To(Equal(uint32(48)))

					classes, err := netlink.ClassList(ifbLink, qdiscs[0].Attrs().Handle)

					Expect(err).NotTo(HaveOccurred())
					Expect(classes).To(HaveLen(2))

					// Uncapped class
					Expect(classes[0]).To(BeAssignableToTypeOf(&netlink.HtbClass{}))
					Expect(classes[0].(*netlink.HtbClass).Handle).To(Equal(netlink.MakeHandle(1, 1)))
					Expect(classes[0].(*netlink.HtbClass).Rate).To(Equal(uint64(UncappedRate)))
					Expect(classes[0].(*netlink.HtbClass).Buffer).To(Equal(uint32(0)))
					Expect(classes[0].(*netlink.HtbClass).Ceil).To(Equal(uint64(UncappedRate)))
					Expect(classes[0].(*netlink.HtbClass).Cbuffer).To(Equal(uint32(0)))

					// Class with traffic shapping settings
					Expect(classes[1]).To(BeAssignableToTypeOf(&netlink.HtbClass{}))
					Expect(classes[1].(*netlink.HtbClass).Handle).To(Equal(netlink.MakeHandle(1, uint16(qdiscs[0].(*netlink.Htb).Defcls))))
					Expect(classes[1].(*netlink.HtbClass).Rate).To(Equal(uint64(1)))
					// Expect(classes[1].(*netlink.HtbClass).Buffer).To(Equal(uint32(15625000)))
					Expect(classes[1].(*netlink.HtbClass).Ceil).To(Equal(uint64(2)))
					Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(Equal(uint32(0)))

					// Since we do not exclude anything from ingress traffic shapping, we should not find any filter
					filters, err := netlink.FilterList(ifbLink, qdiscs[0].Attrs().Handle)
					Expect(err).NotTo(HaveOccurred())
					Expect(filters).To(HaveLen(0))
					return nil
				})).To(Succeed())
			})

			It(fmt.Sprintf("[%s] works with a Veth pair wiht some ipv4 and ipv6 unbounded traffic", ver), func() {
				conf := fmt.Sprintf(`{
				"cniVersion": "%s",
				"name": "cni-plugin-bandwidth-test",
				"type": "bandwidth",
				"ingressRate": 8,
				"ingressBurst": 8,
				"egressRate": 16,
				"egressBurst": 12,
				"nonShapedSubnets": [
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
				Expect(hostNs.Do(func(netNS ns.NetNS) error {
					defer GinkgoRecover()
					r, out, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
					Expect(err).NotTo(HaveOccurred(), string(out))
					result, err := types100.GetResult(r)
					Expect(err).NotTo(HaveOccurred())

					Expect(result.Interfaces).To(HaveLen(3))
					Expect(result.Interfaces[2].Name).To(Equal(ifbDeviceName))
					Expect(result.Interfaces[2].Sandbox).To(Equal(""))

					ifbLink, err := netlink.LinkByName(ifbDeviceName)
					Expect(err).NotTo(HaveOccurred())
					Expect(ifbLink.Attrs().MTU).To(Equal(hostIfaceMTU))

					qdiscs, err := netlink.QdiscList(ifbLink)
					Expect(err).NotTo(HaveOccurred())

					Expect(qdiscs).To(HaveLen(1))
					Expect(qdiscs[0].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))

					Expect(qdiscs[0]).To(BeAssignableToTypeOf(&netlink.Htb{}))

					classes, err := netlink.ClassList(ifbLink, qdiscs[0].Attrs().Handle)

					Expect(err).NotTo(HaveOccurred())
					Expect(classes).To(HaveLen(2))

					// Uncapped class
					Expect(classes[0]).To(BeAssignableToTypeOf(&netlink.HtbClass{}))
					Expect(classes[0].(*netlink.HtbClass).Handle).To(Equal(netlink.MakeHandle(1, 1)))
					Expect(classes[0].(*netlink.HtbClass).Rate).To(Equal(uint64(UncappedRate)))
					Expect(classes[0].(*netlink.HtbClass).Buffer).To(Equal(uint32(0)))
					Expect(classes[0].(*netlink.HtbClass).Ceil).To(Equal(uint64(UncappedRate)))
					Expect(classes[0].(*netlink.HtbClass).Cbuffer).To(Equal(uint32(0)))

					// Class with traffic shapping settings
					Expect(classes[1]).To(BeAssignableToTypeOf(&netlink.HtbClass{}))
					Expect(classes[1].(*netlink.HtbClass).Handle).To(Equal(netlink.MakeHandle(1, uint16(qdiscs[0].(*netlink.Htb).Defcls))))
					Expect(classes[1].(*netlink.HtbClass).Rate).To(Equal(uint64(2)))
					// Expect(classes[1].(*netlink.HtbClass).Buffer).To(Equal(uint32(7812500)))
					Expect(classes[1].(*netlink.HtbClass).Ceil).To(Equal(uint64(4)))
					Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(Equal(uint32(0)))

					filters, err := netlink.FilterList(ifbLink, qdiscs[0].Attrs().Handle)
					Expect(err).NotTo(HaveOccurred())
					Expect(filters).To(HaveLen(2))

					// traffic to 10.0.0.0/8 redirected to uncapped class
					Expect(filters[0]).To(BeAssignableToTypeOf(&netlink.U32{}))
					Expect(filters[0].(*netlink.U32).Actions).To(HaveLen(0))
					Expect(filters[0].Attrs().Protocol).To(Equal(uint16(syscall.ETH_P_ALL)))
					Expect(filters[0].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))
					Expect(filters[0].Attrs().Priority).To(Equal(uint16(16)))
					Expect(filters[0].Attrs().Parent).To(Equal(qdiscs[0].Attrs().Handle))
					Expect(filters[0].(*netlink.U32).ClassId).To(Equal(netlink.MakeHandle(1, 1)))

					filterSel := filters[0].(*netlink.U32).Sel
					Expect(filterSel).To(BeAssignableToTypeOf(&netlink.TcU32Sel{}))
					Expect(filterSel.Flags).To(Equal(uint8(netlink.TC_U32_TERMINAL)))
					Expect(filterSel.Keys).To(HaveLen(1))
					Expect(filterSel.Nkeys).To(Equal(uint8(1)))

					// The filter should match to 10.0.0.0/8 dst address in other words it should be:
					// match 0a000000/ff000000 at 16
					selKey := filterSel.Keys[0]
					Expect(selKey.Val).To(Equal(uint32(10 * math.Pow(256, 3))))
					Expect(selKey.Off).To(Equal(int32(16)))
					Expect(selKey.Mask).To(Equal(uint32(255 * math.Pow(256, 3))))

					// traffic to fd00:db8:abcd:1234:e000::/68 redirected to uncapped class
					Expect(filters[1]).To(BeAssignableToTypeOf(&netlink.U32{}))
					Expect(filters[1].(*netlink.U32).Actions).To(HaveLen(0))
					Expect(filters[1].Attrs().Protocol).To(Equal(uint16(syscall.ETH_P_ALL)))
					Expect(filters[1].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))
					Expect(filters[1].Attrs().Priority).To(Equal(uint16(16)))
					Expect(filters[1].Attrs().Parent).To(Equal(qdiscs[0].Attrs().Handle))
					Expect(filters[1].(*netlink.U32).ClassId).To(Equal(netlink.MakeHandle(1, 1)))

					filterSel = filters[1].(*netlink.U32).Sel
					Expect(filterSel).To(BeAssignableToTypeOf(&netlink.TcU32Sel{}))
					Expect(filterSel.Flags).To(Equal(uint8(netlink.TC_U32_TERMINAL)))
					Expect(filterSel.Keys).To(HaveLen(3))
					Expect(filterSel.Nkeys).To(Equal(uint8(3)))

					// The filter should match to fd00:db8:abcd:1234:e000::/68 dst address in other words it should be:
					// match 0xfd000db8/0xffffffff at 24
					// match 0xabcd1234/0xffffffff at 28
					// match 0xe0000000/0xf0000000 at 32
					// (and last match discarded because it would be equivalent to a matchall/true condition at 36)
					Expect(filterSel.Keys[0].Off).To(Equal(int32(24)))
					Expect(filterSel.Keys[0].Val).To(Equal(uint32(4244639160)))
					Expect(filterSel.Keys[0].Mask).To(Equal(uint32(4294967295)))

					Expect(filterSel.Keys[1].Off).To(Equal(int32(28)))
					Expect(filterSel.Keys[1].Val).To(Equal(uint32(2882343476)))
					Expect(filterSel.Keys[1].Mask).To(Equal(uint32(4294967295)))

					Expect(filterSel.Keys[2].Off).To(Equal(int32(32)))
					Expect(filterSel.Keys[2].Val).To(Equal(uint32(3758096384)))
					Expect(filterSel.Keys[2].Mask).To(Equal(uint32(4026531840)))

					hostVethLink, err := netlink.LinkByName(hostIfname)
					Expect(err).NotTo(HaveOccurred())

					qdiscFilters, err := netlink.FilterList(hostVethLink, netlink.MakeHandle(0xffff, 0))
					Expect(err).NotTo(HaveOccurred())

					Expect(qdiscFilters).To(HaveLen(1))
					Expect(qdiscFilters[0].(*netlink.U32).Actions[0].(*netlink.MirredAction).Ifindex).To(Equal(ifbLink.Attrs().Index))

					return nil
				})).To(Succeed())

				// Container ingress (host egress)
				Expect(hostNs.Do(func(n ns.NetNS) error {
					defer GinkgoRecover()

					ifbLink, err := netlink.LinkByName(hostIfname)
					Expect(err).NotTo(HaveOccurred())

					qdiscs, err := netlink.QdiscList(ifbLink)
					Expect(err).NotTo(HaveOccurred())

					Expect(qdiscs).To(HaveLen(2))
					Expect(qdiscs[0].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))

					Expect(qdiscs[0]).To(BeAssignableToTypeOf(&netlink.Htb{}))
					Expect(qdiscs[0].(*netlink.Htb).Defcls).To(Equal(uint32(48)))

					classes, err := netlink.ClassList(ifbLink, qdiscs[0].Attrs().Handle)

					Expect(err).NotTo(HaveOccurred())
					Expect(classes).To(HaveLen(2))

					// Uncapped class
					Expect(classes[0]).To(BeAssignableToTypeOf(&netlink.HtbClass{}))
					Expect(classes[0].(*netlink.HtbClass).Handle).To(Equal(netlink.MakeHandle(1, 1)))
					Expect(classes[0].(*netlink.HtbClass).Rate).To(Equal(uint64(UncappedRate)))
					Expect(classes[0].(*netlink.HtbClass).Buffer).To(Equal(uint32(0)))
					Expect(classes[0].(*netlink.HtbClass).Ceil).To(Equal(uint64(UncappedRate)))
					Expect(classes[0].(*netlink.HtbClass).Cbuffer).To(Equal(uint32(0)))

					// Class with traffic shapping settings
					Expect(classes[1]).To(BeAssignableToTypeOf(&netlink.HtbClass{}))
					Expect(classes[1].(*netlink.HtbClass).Handle).To(Equal(netlink.MakeHandle(1, uint16(qdiscs[0].(*netlink.Htb).Defcls))))
					Expect(classes[1].(*netlink.HtbClass).Rate).To(Equal(uint64(1)))
					// Expect(classes[1].(*netlink.HtbClass).Buffer).To(Equal(uint32(15625000)))
					Expect(classes[1].(*netlink.HtbClass).Ceil).To(Equal(uint64(2)))
					Expect(classes[1].(*netlink.HtbClass).Cbuffer).To(Equal(uint32(0)))

					filters, err := netlink.FilterList(ifbLink, qdiscs[0].Attrs().Handle)
					Expect(err).NotTo(HaveOccurred())
					Expect(filters).To(HaveLen(2))

					// traffic to 10.0.0.0/8 redirected to uncapped class
					Expect(filters[0]).To(BeAssignableToTypeOf(&netlink.U32{}))
					Expect(filters[0].(*netlink.U32).Actions).To(HaveLen(0))
					Expect(filters[0].Attrs().Protocol).To(Equal(uint16(syscall.ETH_P_ALL)))
					Expect(filters[0].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))
					Expect(filters[0].Attrs().Priority).To(Equal(uint16(16)))
					Expect(filters[0].Attrs().Parent).To(Equal(qdiscs[0].Attrs().Handle))
					Expect(filters[0].(*netlink.U32).ClassId).To(Equal(netlink.MakeHandle(1, 1)))

					filterSel := filters[0].(*netlink.U32).Sel
					Expect(filterSel).To(BeAssignableToTypeOf(&netlink.TcU32Sel{}))
					Expect(filterSel.Flags).To(Equal(uint8(netlink.TC_U32_TERMINAL)))
					Expect(filterSel.Keys).To(HaveLen(1))
					Expect(filterSel.Nkeys).To(Equal(uint8(1)))

					// The filter should match to 10.0.0.0/8 dst address in other words it should be:
					// match 0a000000/ff000000 at 16
					selKey := filterSel.Keys[0]
					Expect(selKey.Val).To(Equal(uint32(10 * math.Pow(256, 3))))
					Expect(selKey.Off).To(Equal(int32(16)))
					Expect(selKey.Mask).To(Equal(uint32(255 * math.Pow(256, 3))))

					// traffic to fd00:db8:abcd:1234:e000::/68 redirected to uncapped class
					Expect(filters[1]).To(BeAssignableToTypeOf(&netlink.U32{}))
					Expect(filters[1].(*netlink.U32).Actions).To(HaveLen(0))
					Expect(filters[1].Attrs().Protocol).To(Equal(uint16(syscall.ETH_P_ALL)))
					Expect(filters[1].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))
					Expect(filters[1].Attrs().Priority).To(Equal(uint16(16)))
					Expect(filters[1].Attrs().Parent).To(Equal(qdiscs[0].Attrs().Handle))
					Expect(filters[1].(*netlink.U32).ClassId).To(Equal(netlink.MakeHandle(1, 1)))

					filterSel = filters[1].(*netlink.U32).Sel
					Expect(filterSel).To(BeAssignableToTypeOf(&netlink.TcU32Sel{}))
					Expect(filterSel.Flags).To(Equal(uint8(netlink.TC_U32_TERMINAL)))
					Expect(filterSel.Keys).To(HaveLen(3))
					Expect(filterSel.Nkeys).To(Equal(uint8(3)))

					// The filter should match to fd00:db8:abcd:1234:e000::/68 dst address in other words it should be:
					// match 0xfd000db8/0xffffffff at 24
					// match 0xabcd1234/0xffffffff at 28
					// match 0xe0000000/0xf0000000 at 32
					// (and last match discarded because it would be equivalent to a matchall/true condition at 36)
					Expect(filterSel.Keys[0].Off).To(Equal(int32(24)))
					Expect(filterSel.Keys[0].Val).To(Equal(uint32(4244639160)))
					Expect(filterSel.Keys[0].Mask).To(Equal(uint32(4294967295)))

					Expect(filterSel.Keys[1].Off).To(Equal(int32(28)))
					Expect(filterSel.Keys[1].Val).To(Equal(uint32(2882343476)))
					Expect(filterSel.Keys[1].Mask).To(Equal(uint32(4294967295)))

					Expect(filterSel.Keys[2].Off).To(Equal(int32(32)))
					Expect(filterSel.Keys[2].Val).To(Equal(uint32(3758096384)))
					Expect(filterSel.Keys[2].Mask).To(Equal(uint32(4026531840)))

					return nil
				})).To(Succeed())
			})
		})

		// It(fmt.Sprintf("[%s] does not apply ingress when disabled", ver), func() {
		// 	conf := fmt.Sprintf(`{
		// 	"cniVersion": "%s",
		// 	"name": "cni-plugin-bandwidth-test",
		// 	"type": "bandwidth",
		// 	"ingressRate": 0,
		// 	"ingressBurst": 0,
		// 	"egressRate": 8000,
		// 	"egressBurst": 80,
		// 	"prevResult": {
		// 		"interfaces": [
		// 			{
		// 				"name": "%s",
		// 				"sandbox": ""
		// 			},
		// 			{
		// 				"name": "%s",
		// 				"sandbox": "%s"
		// 			}
		// 		],
		// 		"ips": [
		// 			{
		// 				"version": "4",
		// 				"address": "%s/24",
		// 				"gateway": "10.0.0.1",
		// 				"interface": 1
		// 			}
		// 		],
		// 		"routes": []
		// 	}
		// }`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

		// 	args := &skel.CmdArgs{
		// 		ContainerID: "dummy",
		// 		Netns:       containerNs.Path(),
		// 		IfName:      containerIfname,
		// 		StdinData:   []byte(conf),
		// 	}

		// 	Expect(hostNs.Do(func(netNS ns.NetNS) error {
		// 		defer GinkgoRecover()

		// 		_, out, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, ifbDeviceName, []byte(conf), func() error { return cmdAdd(args) })
		// 		Expect(err).NotTo(HaveOccurred(), string(out))

		// 		_, err = netlink.LinkByName(ifbDeviceName)
		// 		Expect(err).NotTo(HaveOccurred())
		// 		return nil
		// 	})).To(Succeed())

		// 	Expect(hostNs.Do(func(n ns.NetNS) error {
		// 		defer GinkgoRecover()

		// 		containerIfLink, err := netlink.LinkByName(hostIfname)
		// 		Expect(err).NotTo(HaveOccurred())

		// 		qdiscs, err := netlink.QdiscList(containerIfLink)
		// 		Expect(err).NotTo(HaveOccurred())

		// 		Expect(qdiscs).To(HaveLen(2))
		// 		Expect(qdiscs[0]).NotTo(BeAssignableToTypeOf(&netlink.Tbf{}))
		// 		Expect(qdiscs[1]).NotTo(BeAssignableToTypeOf(&netlink.Tbf{}))

		// 		return nil
		// 	})).To(Succeed())
		// })
	}
})

// 	It(fmt.Sprintf("[%s] does not apply egress when disabled", ver), func() {
// 		conf := fmt.Sprintf(`{
// 			"cniVersion": "%s",
// 			"name": "cni-plugin-bandwidth-test",
// 			"type": "bandwidth",
// 			"egressRate": 0,
// 			"egressBurst": 0,
// 			"ingressRate": 8000,
// 			"ingressBurst": 80,
// 			"prevResult": {
// 				"interfaces": [
// 					{
// 						"name": "%s",
// 						"sandbox": ""
// 					},
// 					{
// 						"name": "%s",
// 						"sandbox": "%s"
// 					}
// 				],
// 				"ips": [
// 					{
// 						"version": "4",
// 						"address": "%s/24",
// 						"gateway": "10.0.0.1",
// 						"interface": 1
// 					}
// 				],
// 				"routes": []
// 			}
// 		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

// 		args := &skel.CmdArgs{
// 			ContainerID: "dummy",
// 			Netns:       containerNs.Path(),
// 			IfName:      containerIfname,
// 			StdinData:   []byte(conf),
// 		}

// 		Expect(hostNs.Do(func(netNS ns.NetNS) error {
// 			defer GinkgoRecover()

// 			_, out, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, ifbDeviceName, []byte(conf), func() error { return cmdAdd(args) })
// 			Expect(err).NotTo(HaveOccurred(), string(out))

// 			_, err = netlink.LinkByName(ifbDeviceName)
// 			Expect(err).To(HaveOccurred())
// 			return nil
// 		})).To(Succeed())

// 		Expect(hostNs.Do(func(n ns.NetNS) error {
// 			defer GinkgoRecover()

// 			containerIfLink, err := netlink.LinkByName(hostIfname)
// 			Expect(err).NotTo(HaveOccurred())

// 			qdiscs, err := netlink.QdiscList(containerIfLink)
// 			Expect(err).NotTo(HaveOccurred())

// 			Expect(qdiscs).To(HaveLen(1))
// 			Expect(qdiscs[0].Attrs().LinkIndex).To(Equal(containerIfLink.Attrs().Index))

// 			Expect(qdiscs[0]).To(BeAssignableToTypeOf(&netlink.Tbf{}))
// 			Expect(qdiscs[0].(*netlink.Tbf).Rate).To(Equal(uint64(1000)))
// 			Expect(qdiscs[0].(*netlink.Tbf).Limit).To(Equal(uint32(35)))
// 			return nil
// 		})).To(Succeed())
// 	})

// 	It(fmt.Sprintf("[%s] fails an invalid ingress config", ver), func() {
// 		conf := fmt.Sprintf(`{
// 			"cniVersion": "%s",
// 			"name": "cni-plugin-bandwidth-test",
// 			"type": "bandwidth",
// 			"ingressRate": 0,
// 			"ingressBurst": 123,
// 			"egressRate": 123,
// 			"egressBurst": 123,
// 			"prevResult": {
// 				"interfaces": [
// 					{
// 						"name": "%s",
// 						"sandbox": ""
// 					},
// 					{
// 						"name": "%s",
// 						"sandbox": "%s"
// 					}
// 				],
// 				"ips": [
// 					{
// 						"version": "4",
// 						"address": "%s/24",
// 						"gateway": "10.0.0.1",
// 						"interface": 1
// 					}
// 				],
// 				"routes": []
// 			}
// 		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

// 		args := &skel.CmdArgs{
// 			ContainerID: "dummy",
// 			Netns:       containerNs.Path(),
// 			IfName:      "eth0",
// 			StdinData:   []byte(conf),
// 		}

// 		Expect(hostNs.Do(func(netNS ns.NetNS) error {
// 			defer GinkgoRecover()

// 			_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
// 			Expect(err).To(MatchError("if burst is set, rate must also be set"))
// 			return nil
// 		})).To(Succeed())
// 	})

// 	It(fmt.Sprintf("[%s] works with a Veth pair using runtime config", ver), func() {
// 		conf := fmt.Sprintf(`{
// 			"cniVersion": "%s",
// 			"name": "cni-plugin-bandwidth-test",
// 			"type": "bandwidth",
// 			"runtimeConfig": {
// 				"bandWidth": {
// 					"ingressRate": 8,
// 					"ingressBurst": 8,
// 					"egressRate": 16,
// 					"egressBurst": 9
// 				}
// 			},
// 			"prevResult": {
// 				"interfaces": [
// 					{
// 						"name": "%s",
// 						"sandbox": ""
// 					},
// 					{
// 						"name": "%s",
// 						"sandbox": "%s"
// 					}
// 				],
// 				"ips": [
// 					{
// 						"version": "4",
// 						"address": "%s/24",
// 						"gateway": "10.0.0.1",
// 						"interface": 1
// 					}
// 				],
// 				"routes": []
// 			}
// 		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

// 		args := &skel.CmdArgs{
// 			ContainerID: "dummy",
// 			Netns:       containerNs.Path(),
// 			IfName:      containerIfname,
// 			StdinData:   []byte(conf),
// 		}

// 		Expect(hostNs.Do(func(netNS ns.NetNS) error {
// 			defer GinkgoRecover()
// 			r, out, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
// 			Expect(err).NotTo(HaveOccurred(), string(out))
// 			result, err := types100.GetResult(r)
// 			Expect(err).NotTo(HaveOccurred())

// 			Expect(result.Interfaces).To(HaveLen(3))
// 			Expect(result.Interfaces[2].Name).To(Equal(ifbDeviceName))
// 			Expect(result.Interfaces[2].Sandbox).To(Equal(""))

// 			ifbLink, err := netlink.LinkByName(ifbDeviceName)
// 			Expect(err).NotTo(HaveOccurred())
// 			Expect(ifbLink.Attrs().MTU).To(Equal(hostIfaceMTU))

// 			qdiscs, err := netlink.QdiscList(ifbLink)
// 			Expect(err).NotTo(HaveOccurred())

// 			Expect(qdiscs).To(HaveLen(1))
// 			Expect(qdiscs[0].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))

// 			Expect(qdiscs[0]).To(BeAssignableToTypeOf(&netlink.Tbf{}))
// 			Expect(qdiscs[0].(*netlink.Tbf).Rate).To(Equal(uint64(2)))
// 			Expect(qdiscs[0].(*netlink.Tbf).Limit).To(Equal(uint32(1)))

// 			hostVethLink, err := netlink.LinkByName(hostIfname)
// 			Expect(err).NotTo(HaveOccurred())

// 			qdiscFilters, err := netlink.FilterList(hostVethLink, netlink.MakeHandle(0xffff, 0))
// 			Expect(err).NotTo(HaveOccurred())

// 			Expect(qdiscFilters).To(HaveLen(1))
// 			Expect(qdiscFilters[0].(*netlink.U32).Actions[0].(*netlink.MirredAction).Ifindex).To(Equal(ifbLink.Attrs().Index))

// 			return nil
// 		})).To(Succeed())

// 		Expect(hostNs.Do(func(n ns.NetNS) error {
// 			defer GinkgoRecover()

// 			ifbLink, err := netlink.LinkByName(hostIfname)
// 			Expect(err).NotTo(HaveOccurred())

// 			qdiscs, err := netlink.QdiscList(ifbLink)
// 			Expect(err).NotTo(HaveOccurred())

// 			Expect(qdiscs).To(HaveLen(2))
// 			Expect(qdiscs[0].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))

// 			Expect(qdiscs[0]).To(BeAssignableToTypeOf(&netlink.Tbf{}))
// 			Expect(qdiscs[0].(*netlink.Tbf).Rate).To(Equal(uint64(1)))
// 			Expect(qdiscs[0].(*netlink.Tbf).Limit).To(Equal(uint32(1)))
// 			return nil
// 		})).To(Succeed())
// 	})

// 	It(fmt.Sprintf("[%s] should apply static config when both static config and runtime config exist", ver), func() {
// 		conf := fmt.Sprintf(`{
// 			"cniVersion": "%s",
// 			"name": "cni-plugin-bandwidth-test",
// 			"type": "bandwidth",
// 			"ingressRate": 0,
// 			"ingressBurst": 123,
// 			"egressRate": 123,
// 			"egressBurst": 123,
// 			"runtimeConfig": {
// 				"bandWidth": {
// 					"ingressRate": 8,
// 					"ingressBurst": 8,
// 					"egressRate": 16,
// 					"egressBurst": 9
// 				}
// 			},
// 			"prevResult": {
// 				"interfaces": [
// 					{
// 						"name": "%s",
// 						"sandbox": ""
// 					},
// 					{
// 						"name": "%s",
// 						"sandbox": "%s"
// 					}
// 				],
// 				"ips": [
// 					{
// 						"version": "4",
// 						"address": "%s/24",
// 						"gateway": "10.0.0.1",
// 						"interface": 1
// 					}
// 				],
// 				"routes": []
// 			}
// 		}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

// 		args := &skel.CmdArgs{
// 			ContainerID: "dummy",
// 			Netns:       containerNs.Path(),
// 			IfName:      "eth0",
// 			StdinData:   []byte(conf),
// 		}

// 		Expect(hostNs.Do(func(netNS ns.NetNS) error {
// 			defer GinkgoRecover()

// 			_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
// 			Expect(err).To(MatchError("if burst is set, rate must also be set"))
// 			return nil
// 		})).To(Succeed())
// 	})
// })

// 		Describe("cmdDEL", func() {
// 			It(fmt.Sprintf("[%s] works with a Veth pair using 0.3.0 config", ver), func() {
// 				conf := fmt.Sprintf(`{
// 					"cniVersion": "%s",
// 					"name": "cni-plugin-bandwidth-test",
// 					"type": "bandwidth",
// 					"ingressRate": 8,
// 					"ingressBurst": 8,
// 					"egressRate": 9,
// 					"egressBurst": 9,
// 					"prevResult": {
// 						"interfaces": [
// 							{
// 								"name": "%s",
// 								"sandbox": ""
// 							},
// 							{
// 								"name": "%s",
// 								"sandbox": "%s"
// 							}
// 						],
// 						"ips": [
// 							{
// 								"version": "4",
// 								"address": "%s/24",
// 								"gateway": "10.0.0.1",
// 								"interface": 1
// 							}
// 						],
// 						"routes": []
// 					}
// 				}`, ver, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

// 				args := &skel.CmdArgs{
// 					ContainerID: "dummy",
// 					Netns:       containerNs.Path(),
// 					IfName:      containerIfname,
// 					StdinData:   []byte(conf),
// 				}

// 				Expect(hostNs.Do(func(netNS ns.NetNS) error {
// 					defer GinkgoRecover()
// 					_, out, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
// 					Expect(err).NotTo(HaveOccurred(), string(out))

// 					err = testutils.CmdDel(containerNs.Path(), args.ContainerID, "", func() error { return cmdDel(args) })
// 					Expect(err).NotTo(HaveOccurred(), string(out))

// 					_, err = netlink.LinkByName(ifbDeviceName)
// 					Expect(err).To(HaveOccurred())

// 					return nil
// 				})).To(Succeed())
// 			})
// 		})

// 		Describe("Getting the host interface which plugin should work on from veth peer of container interface", func() {
// 			It(fmt.Sprintf("[%s] should work with multiple host veth interfaces", ver), func() {
// 				// create veth peer in host ns
// 				vethName, peerName := "host-veth-peer1", "host-veth-peer2"
// 				createVethInOneNs(hostNs, vethName, peerName)

// 				conf := fmt.Sprintf(`{
// 					"cniVersion": "%s",
// 					"name": "cni-plugin-bandwidth-test",
// 					"type": "bandwidth",
// 					"ingressRate": 8,
// 					"ingressBurst": 8,
// 					"egressRate": 16,
// 					"egressBurst": 8,
// 					"prevResult": {
// 						"interfaces": [
// 							{
// 								"name": "%s",
// 								"sandbox": ""
// 							},
// 							{
// 								"name": "%s",
// 								"sandbox": ""
// 							},
// 							{
// 								"name": "%s",
// 								"sandbox": ""
// 							},
// 							{
// 								"name": "%s",
// 								"sandbox": "%s"
// 							}
// 						],
// 						"ips": [
// 							{
// 								"version": "4",
// 								"address": "%s/24",
// 								"gateway": "10.0.0.1",
// 								"interface": 1
// 							}
// 						],
// 						"routes": []
// 					}
// 				}`, ver, vethName, peerName, hostIfname, containerIfname, containerNs.Path(), containerIP.String())

// 				args := &skel.CmdArgs{
// 					ContainerID: "dummy",
// 					Netns:       containerNs.Path(),
// 					IfName:      containerIfname,
// 					StdinData:   []byte(conf),
// 				}

// 				Expect(hostNs.Do(func(netNS ns.NetNS) error {
// 					defer GinkgoRecover()
// 					r, out, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
// 					Expect(err).NotTo(HaveOccurred(), string(out))
// 					result, err := types100.GetResult(r)
// 					Expect(err).NotTo(HaveOccurred())

// 					Expect(result.Interfaces).To(HaveLen(5))
// 					Expect(result.Interfaces[4].Name).To(Equal(ifbDeviceName))
// 					Expect(result.Interfaces[4].Sandbox).To(Equal(""))

// 					ifbLink, err := netlink.LinkByName(ifbDeviceName)
// 					Expect(err).NotTo(HaveOccurred())
// 					Expect(ifbLink.Attrs().MTU).To(Equal(hostIfaceMTU))

// 					qdiscs, err := netlink.QdiscList(ifbLink)
// 					Expect(err).NotTo(HaveOccurred())

// 					Expect(qdiscs).To(HaveLen(1))
// 					Expect(qdiscs[0].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))

// 					Expect(qdiscs[0]).To(BeAssignableToTypeOf(&netlink.Tbf{}))
// 					Expect(qdiscs[0].(*netlink.Tbf).Rate).To(Equal(uint64(2)))
// 					Expect(qdiscs[0].(*netlink.Tbf).Limit).To(Equal(uint32(1)))

// 					hostVethLink, err := netlink.LinkByName(hostIfname)
// 					Expect(err).NotTo(HaveOccurred())

// 					qdiscFilters, err := netlink.FilterList(hostVethLink, netlink.MakeHandle(0xffff, 0))
// 					Expect(err).NotTo(HaveOccurred())

// 					Expect(qdiscFilters).To(HaveLen(1))
// 					Expect(qdiscFilters[0].(*netlink.U32).Actions[0].(*netlink.MirredAction).Ifindex).To(Equal(ifbLink.Attrs().Index))

// 					return nil
// 				})).To(Succeed())

// 				Expect(hostNs.Do(func(n ns.NetNS) error {
// 					defer GinkgoRecover()

// 					ifbLink, err := netlink.LinkByName(hostIfname)
// 					Expect(err).NotTo(HaveOccurred())

// 					qdiscs, err := netlink.QdiscList(ifbLink)
// 					Expect(err).NotTo(HaveOccurred())

// 					Expect(qdiscs).To(HaveLen(2))
// 					Expect(qdiscs[0].Attrs().LinkIndex).To(Equal(ifbLink.Attrs().Index))

// 					Expect(qdiscs[0]).To(BeAssignableToTypeOf(&netlink.Htb{}))
// 					Expect(qdiscs[0].(*netlink.Htb).Defcls).To(Equal(48))

// 					classes, err := netlink.ClassList(ifbLink, qdiscs[0].Attrs().Handle)
// 					Expect(err).NotTo(HaveOccurred())
// 					Expect(classes).To(HaveLen(2))

// 					Expect(classes[0]).To(BeAssignableToTypeOf(&netlink.HtbClass{}))
// 					Expect(classes[0].(*netlink.HtbClass).Handle).To(Equal(netlink.MakeHandle(1, uint16(qdiscs[0].(*netlink.Htb).Defcls))))
// 					return nil
// 				})).To(Succeed())
// 			})

// 			It(fmt.Sprintf("[%s] should fail when container interface has no veth peer", ver), func() {
// 				// create a macvlan device to be container interface
// 				macvlanContainerIfname := "container-macv"
// 				createMacvlan(containerNs, containerIfname, macvlanContainerIfname)

// 				conf := fmt.Sprintf(`{
// 					"cniVersion": "%s",
// 					"name": "cni-plugin-bandwidth-test",
// 					"type": "bandwidth",
// 					"ingressRate": 8,
// 					"ingressBurst": 8,
// 					"egressRate": 16,
// 					"egressBurst": 8,
// 					"prevResult": {
// 						"interfaces": [
// 							{
// 								"name": "%s",
// 								"sandbox": ""
// 							},
// 							{
// 								"name": "%s",
// 								"sandbox": "%s"
// 							}
// 						],
// 						"ips": [
// 							{
// 								"version": "4",
// 								"address": "%s/24",
// 								"gateway": "10.0.0.1",
// 								"interface": 1
// 							}
// 						],
// 						"routes": []
// 					}
// 				}`, ver, hostIfname, macvlanContainerIfname, containerNs.Path(), containerIP.String())

// 				args := &skel.CmdArgs{
// 					ContainerID: "dummy",
// 					Netns:       containerNs.Path(),
// 					IfName:      macvlanContainerIfname,
// 					StdinData:   []byte(conf),
// 				}

// 				Expect(hostNs.Do(func(netNS ns.NetNS) error {
// 					defer GinkgoRecover()

// 					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
// 					Expect(err).To(HaveOccurred())

// 					return nil
// 				})).To(Succeed())
// 			})

// 			It(fmt.Sprintf("[%s] should fail when preResult has no interfaces", ver), func() {
// 				conf := fmt.Sprintf(`{
// 					"cniVersion": "%s",
// 					"name": "cni-plugin-bandwidth-test",
// 					"type": "bandwidth",
// 					"ingressRate": 8,
// 					"ingressBurst": 8,
// 					"egressRate": 16,
// 					"egressBurst": 8,
// 					"prevResult": {
// 						"interfaces": [],
// 						"ips": [],
// 						"routes": []
// 					}
// 				}`, ver)

// 				args := &skel.CmdArgs{
// 					ContainerID: "dummy",
// 					Netns:       containerNs.Path(),
// 					IfName:      "eth0",
// 					StdinData:   []byte(conf),
// 				}

// 				Expect(hostNs.Do(func(netNS ns.NetNS) error {
// 					defer GinkgoRecover()

// 					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
// 					Expect(err).To(HaveOccurred())

// 					return nil
// 				})).To(Succeed())
// 			})

// 			It(fmt.Sprintf("[%s] should fail when veth peer of container interface does not match any of host interfaces in preResult", ver), func() {
// 				// fake a non-exist host interface name
// 				fakeHostIfname := fmt.Sprintf("%s-fake", hostIfname)

// 				conf := fmt.Sprintf(`{
// 					"cniVersion": "%s",
// 					"name": "cni-plugin-bandwidth-test",
// 					"type": "bandwidth",
// 					"ingressRate": 8,
// 					"ingressBurst": 8,
// 					"egressRate": 16,
// 					"egressBurst": 8,
// 					"prevResult": {
// 						"interfaces": [
// 							{
// 								"name": "%s",
// 								"sandbox": ""
// 							},
// 							{
// 								"name": "%s",
// 								"sandbox": "%s"
// 							}
// 						],
// 						"ips": [
// 							{
// 								"version": "4",
// 								"address": "%s/24",
// 								"gateway": "10.0.0.1",
// 								"interface": 1
// 							}
// 						],
// 						"routes": []
// 					}
// 				}`, ver, fakeHostIfname, containerIfname, containerNs.Path(), containerIP.String())

// 				args := &skel.CmdArgs{
// 					ContainerID: "dummy",
// 					Netns:       containerNs.Path(),
// 					IfName:      containerIfname,
// 					StdinData:   []byte(conf),
// 				}

// 				Expect(hostNs.Do(func(netNS ns.NetNS) error {
// 					defer GinkgoRecover()

// 					_, _, err := testutils.CmdAdd(containerNs.Path(), args.ContainerID, "", []byte(conf), func() error { return cmdAdd(args) })
// 					Expect(err).To(HaveOccurred())

// 					return nil
// 				})).To(Succeed())
// 			})
// 		})

// 		Context(fmt.Sprintf("[%s] when chaining bandwidth plugin with PTP", ver), func() {
// 			var ptpConf string
// 			var rateInBits uint64
// 			var burstInBits uint64
// 			var packetInBytes int
// 			var containerWithoutTbfNS ns.NetNS
// 			var containerWithTbfNS ns.NetNS
// 			var portServerWithTbf int
// 			var portServerWithoutTbf int

// 			var containerWithTbfRes types.Result
// 			var containerWithoutTbfRes types.Result
// 			var echoServerWithTbf *gexec.Session
// 			var echoServerWithoutTbf *gexec.Session
// 			var dataDir string

// 			BeforeEach(func() {
// 				rateInBytes := 1000
// 				rateInBits = uint64(rateInBytes * 8)
// 				burstInBits = rateInBits * 2
// 				packetInBytes = rateInBytes * 25

// 				var err error
// 				dataDir, err = os.MkdirTemp("", "bandwidth_linux_test")
// 				Expect(err).NotTo(HaveOccurred())

// 				ptpConf = fmt.Sprintf(`{
// 				    "cniVersion": "%s",
// 				    "name": "myBWnet",
// 				    "type": "ptp",
// 				    "ipMasq": true,
// 				    "mtu": 512,
// 				    "ipam": {
// 					"type": "host-local",
// 					"subnet": "10.1.2.0/24",
// 					"dataDir": "%s"
// 				    }
// 				}`, ver, dataDir)

// 				const (
// 					containerWithTbfIFName    = "ptp0"
// 					containerWithoutTbfIFName = "ptp1"
// 				)

// 				containerWithTbfNS, err = testutils.NewNS()
// 				Expect(err).NotTo(HaveOccurred())

// 				containerWithoutTbfNS, err = testutils.NewNS()
// 				Expect(err).NotTo(HaveOccurred())

// 				By("create two containers, and use the bandwidth plugin on one of them")
// 				Expect(hostNs.Do(func(ns.NetNS) error {
// 					defer GinkgoRecover()

// 					containerWithTbfRes, _, err = testutils.CmdAdd(containerWithTbfNS.Path(), "dummy", containerWithTbfIFName, []byte(ptpConf), func() error {
// 						r, err := invoke.DelegateAdd(context.TODO(), "ptp", []byte(ptpConf), nil)
// 						Expect(err).NotTo(HaveOccurred())
// 						Expect(r.Print()).To(Succeed())

// 						return err
// 					})
// 					Expect(err).NotTo(HaveOccurred())

// 					containerWithoutTbfRes, _, err = testutils.CmdAdd(containerWithoutTbfNS.Path(), "dummy2", containerWithoutTbfIFName, []byte(ptpConf), func() error {
// 						r, err := invoke.DelegateAdd(context.TODO(), "ptp", []byte(ptpConf), nil)
// 						Expect(err).NotTo(HaveOccurred())
// 						Expect(r.Print()).To(Succeed())

// 						return err
// 					})
// 					Expect(err).NotTo(HaveOccurred())

// 					containerWithTbfResult, err := types100.GetResult(containerWithTbfRes)
// 					Expect(err).NotTo(HaveOccurred())

// 					tbfPluginConf := &PluginConf{}
// 					err = json.Unmarshal([]byte(ptpConf), &tbfPluginConf)
// 					Expect(err).NotTo(HaveOccurred())

// 					tbfPluginConf.RuntimeConfig.Bandwidth = &BandwidthEntry{
// 						IngressBurst: burstInBits,
// 						IngressRate:  rateInBits,
// 						EgressBurst:  burstInBits,
// 						EgressRate:   rateInBits,
// 					}
// 					tbfPluginConf.Type = "bandwidth"
// 					newConfBytes, err := buildOneConfig("myBWnet", ver, tbfPluginConf, containerWithTbfResult)
// 					Expect(err).NotTo(HaveOccurred())

// 					args := &skel.CmdArgs{
// 						ContainerID: "dummy3",
// 						Netns:       containerWithTbfNS.Path(),
// 						IfName:      containerWithTbfIFName,
// 						StdinData:   newConfBytes,
// 					}

// 					result, out, err := testutils.CmdAdd(containerWithTbfNS.Path(), args.ContainerID, "", newConfBytes, func() error { return cmdAdd(args) })
// 					Expect(err).NotTo(HaveOccurred(), string(out))

// 					if testutils.SpecVersionHasCHECK(ver) {
// 						// Do CNI Check
// 						checkConf := &PluginConf{}
// 						err = json.Unmarshal([]byte(ptpConf), &checkConf)
// 						Expect(err).NotTo(HaveOccurred())

// 						checkConf.RuntimeConfig.Bandwidth = &BandwidthEntry{
// 							IngressBurst: burstInBits,
// 							IngressRate:  rateInBits,
// 							EgressBurst:  burstInBits,
// 							EgressRate:   rateInBits,
// 						}
// 						checkConf.Type = "bandwidth"

// 						newCheckBytes, err := buildOneConfig("myBWnet", ver, checkConf, result)
// 						Expect(err).NotTo(HaveOccurred())

// 						args = &skel.CmdArgs{
// 							ContainerID: "dummy3",
// 							Netns:       containerWithTbfNS.Path(),
// 							IfName:      containerWithTbfIFName,
// 							StdinData:   newCheckBytes,
// 						}

// 						err = testutils.CmdCheck(containerWithTbfNS.Path(), args.ContainerID, "", func() error { return cmdCheck(args) })
// 						Expect(err).NotTo(HaveOccurred())
// 					}

// 					return nil
// 				})).To(Succeed())

// 				By("starting a tcp server on both containers")
// 				portServerWithTbf, echoServerWithTbf = startEchoServerInNamespace(containerWithTbfNS)
// 				portServerWithoutTbf, echoServerWithoutTbf = startEchoServerInNamespace(containerWithoutTbfNS)
// 			})

// 			AfterEach(func() {
// 				Expect(os.RemoveAll(dataDir)).To(Succeed())

// 				Expect(containerWithTbfNS.Close()).To(Succeed())
// 				Expect(testutils.UnmountNS(containerWithTbfNS)).To(Succeed())
// 				Expect(containerWithoutTbfNS.Close()).To(Succeed())
// 				Expect(testutils.UnmountNS(containerWithoutTbfNS)).To(Succeed())

// 				if echoServerWithoutTbf != nil {
// 					echoServerWithoutTbf.Kill()
// 				}
// 				if echoServerWithTbf != nil {
// 					echoServerWithTbf.Kill()
// 				}
// 			})

// 			Measure("limits ingress traffic on veth device", func(b Benchmarker) {
// 				var runtimeWithLimit time.Duration
// 				var runtimeWithoutLimit time.Duration

// 				By("gather timing statistics about both containers")
// 				By("sending tcp traffic to the container that has traffic shaped", func() {
// 					runtimeWithLimit = b.Time("with tbf", func() {
// 						result, err := types100.GetResult(containerWithTbfRes)
// 						Expect(err).NotTo(HaveOccurred())

// 						makeTCPClientInNS(hostNs.Path(), result.IPs[0].Address.IP.String(), portServerWithTbf, packetInBytes)
// 					})
// 				})

// 				By("sending tcp traffic to the container that does not have traffic shaped", func() {
// 					runtimeWithoutLimit = b.Time("without tbf", func() {
// 						result, err := types100.GetResult(containerWithoutTbfRes)
// 						Expect(err).NotTo(HaveOccurred())

// 						makeTCPClientInNS(hostNs.Path(), result.IPs[0].Address.IP.String(), portServerWithoutTbf, packetInBytes)
// 					})
// 				})

// 				Expect(runtimeWithLimit).To(BeNumerically(">", runtimeWithoutLimit+1000*time.Millisecond))
// 			}, 1)
// 		})
// 	}

// 	Describe("Validating input", func() {
// 		It("Should allow only 4GB burst rate", func() {
// 			err := validateRateAndBurst(5000, 4*1024*1024*1024*8-16) // 2 bytes less than the max should pass
// 			Expect(err).NotTo(HaveOccurred())
// 			err = validateRateAndBurst(5000, 4*1024*1024*1024*8) // we're 1 bit above MaxUint32
// 			Expect(err).To(HaveOccurred())
// 			err = validateRateAndBurst(0, 1)
// 			Expect(err).To(HaveOccurred())
// 			err = validateRateAndBurst(1, 0)
// 			Expect(err).To(HaveOccurred())
// 			err = validateRateAndBurst(0, 0)
// 			Expect(err).NotTo(HaveOccurred())
// 		})
// 	})
// })
