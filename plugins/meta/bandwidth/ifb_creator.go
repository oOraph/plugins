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
	"net"
	"os/exec"
	"syscall"

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/plugins/pkg/ip"
)

const latencyInMillis = 25

func CreateIfb(ifbDeviceName string, mtu int) error {
	err := netlink.LinkAdd(&netlink.Ifb{
		LinkAttrs: netlink.LinkAttrs{
			Name:  ifbDeviceName,
			Flags: net.FlagUp,
			MTU:   mtu,
		},
	})
	if err != nil {
		return fmt.Errorf("adding link: %s", err)
	}

	return nil
}

func TeardownIfb(deviceName string) error {
	_, err := ip.DelLinkByNameAddr(deviceName)
	if err != nil && err == ip.ErrLinkNotFound {
		return nil
	}
	return err
}

func CreateIngressQdisc(rateInBits, burstInBits uint64, excludeSubnets []string, hostDeviceName string) error {
	// hostDevice, err := netlink.LinkByName(hostDeviceName)
	// if err != nil {
	// 	return fmt.Errorf("get host device: %s", err)
	// }
	return createHTB(rateInBits, burstInBits, hostDeviceName, excludeSubnets)
}

func CreateEgressQdisc(rateInBits, burstInBits uint64, excludeSubnets []string, hostDeviceName string, ifbDeviceName string) error {

	ifbDevice, err := netlink.LinkByName(ifbDeviceName)
	if err != nil {
		return fmt.Errorf("get ifb device: %s", err)
	}
	hostDevice, err := netlink.LinkByName(hostDeviceName)
	if err != nil {
		return fmt.Errorf("get host device: %s", err)
	}

	// add qdisc ingress on host device
	ingress := &netlink.Ingress{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: hostDevice.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0), // ffff:
			Parent:    netlink.HANDLE_INGRESS,
		},
	}

	err = netlink.QdiscAdd(ingress)
	if err != nil {
		return fmt.Errorf("create ingress qdisc: %s", err)
	}

	// add filter on host device to mirror traffic to ifb device
	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: hostDevice.Attrs().Index,
			Parent:    ingress.QdiscAttrs.Handle,
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		ClassId:    netlink.MakeHandle(1, 1),
		RedirIndex: ifbDevice.Attrs().Index,
		Actions: []netlink.Action{
			&netlink.MirredAction{
				ActionAttrs:  netlink.ActionAttrs{},
				MirredAction: netlink.TCA_EGRESS_REDIR,
				Ifindex:      ifbDevice.Attrs().Index,
			},
		},
	}
	err = netlink.FilterAdd(filter)
	if err != nil {
		return fmt.Errorf("add filter: %s", err)
	}

	// throttle traffic on ifb device
	err = createHTB(rateInBits, burstInBits, ifbDevice.Attrs().Name, excludeSubnets)
	if err != nil {
		return fmt.Errorf("create ifb qdisc: %s", err)
	}
	return nil
}

func createHTB(rateInBits, burstInBits uint64, interfaceName string, excludeSubnets []string) error {

	// Netlink struct fields are not clear, let's use shell

	// Step 1 qdisc
	cmdStr := fmt.Sprintf("/usr/sbin/tc qdisc add dev %s root handle 1: htb default 30", interfaceName)
	cmd := exec.Command(cmdStr)
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("error while creating qdisc: %s", err)
	}

	// Step 2 classes

	// The capped one for all but excluded subnets
	cmdStr = fmt.Sprintf("/usr/sbin/tc class add dev %s parent 1: classid 1:30 htb rate %d burst %d",
		interfaceName, rateInBits, burstInBits)
	cmd = exec.Command(cmdStr)
	_, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("error while creating tc qdisc: %s", err)
	}

	// The "uncapped" one (did not know how to uncap so I capped it to very high)
	cmdStr = fmt.Sprintf("/usr/sbin/tc class add dev %s parent 1: classid 1:1 htb rate %d burst %d",
		interfaceName, 100000000000, 4000000000)
	cmd = exec.Command(cmdStr)
	_, err = cmd.Output()
	if err != nil {
		return fmt.Errorf("error while creating tc class: %s", err)
	}

	// Now add filter to redirect excluded subnets to the class 1 instead of the default one (30)

	for _, subnet := range excludeSubnets {
		_, nw, err := net.ParseCIDR(subnet)
		if err != nil {
			return fmt.Errorf("bad subnet %s: %s", subnet, err)
		}

		isIpv4 := nw.IP.To4() != nil
		protocol := "ip6"
		if isIpv4 {
			protocol = "ip"
		}
		cmdStr = fmt.Sprintf("/usr/sbin/tc filter add dev %s parent 1: protocol %s prio 16 u32 match ip dst %s flowid 1:1",
			interfaceName, protocol, subnet)
		cmd = exec.Command(cmdStr)
		_, err = cmd.Output()
		if err != nil {
			return fmt.Errorf("error while creating tc filter: %s", err)
		}
	}

	// // Equivalent to
	// // tc qdisc add dev link root htb handle :1 default 1
	// if rateInBits <= 0 {
	// 	return fmt.Errorf("invalid rate: %d", rateInBits)
	// }
	// if burstInBits <= 0 {
	// 	return fmt.Errorf("invalid burst: %d", burstInBits)
	// }
	// rateInBytes := rateInBits / 8
	// burstInBytes := burstInBits / 8
	// bufferInBytes := buffer(rateInBytes, uint32(burstInBytes))
	// // latency := latencyInUsec(latencyInMillis)
	// // limitInBytes := limit(rateInBytes, latency, uint32(burstInBytes))

	// qdisc := &netlink.Htb{
	// 	QdiscAttrs: netlink.QdiscAttrs{
	// 		LinkIndex: linkIndex,
	// 		Handle:    netlink.MakeHandle(1, 0),
	// 		Parent:    netlink.HANDLE_ROOT,
	// 	},
	// 	Defcls: 1,
	// }

	// err := netlink.QdiscAdd(qdisc)
	// if err != nil {
	// 	return fmt.Errorf("create qdisc: %s", err)
	// }

	// // Now we create two classes, the class 1 subject to the rate limit
	// // And another class that will concern all the subnets we want to exclude from QoS

	// class1 := &netlink.HtbClass{
	// 	ClassAttrs: netlink.ClassAttrs{
	// 		LinkIndex: qdisc.LinkIndex,
	// 		Handle:    netlink.MakeHandle(1, 1),
	// 		Parent:    qdisc.Handle,
	// 	},
	// 	Rate:   rateInBytes,
	// 	Buffer: bufferInBytes,
	// }

	// err = netlink.ClassAdd(class1)
	// if err != nil {
	// 	return fmt.Errorf("create default htb class: %s", err)
	// }

	// uncappedRate := ^uint64(0)
	// uncappedBuffer := buffer(uncappedRate, uint32(4000000000))
	// class2 := &netlink.HtbClass{
	// 	ClassAttrs: netlink.ClassAttrs{
	// 		LinkIndex: qdisc.LinkIndex,
	// 		Handle:    netlink.MakeHandle(1, 2),
	// 		Parent:    qdisc.Handle,
	// 	},
	// 	Rate:   uncappedRate,
	// 	Buffer: uncappedBuffer,
	// }

	// err = netlink.ClassAdd(class2)
	// if err != nil {
	// 	return fmt.Errorf("create unshaped htb class: %s", err)
	// }

	// filters := make([]netlink.U32, 0, 10)

	// for _, subnet := range subnets {

	// 	_, nw, err := net.ParseCIDR(subnet)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	isIpv4 := nw.IP.To4() != nil
	// 	protocol := syscall.IPPROTO_IPV6
	// 	if isIpv4 {
	// 		protocol = syscall.IPPROTO_IPIP
	// 	}

	// 	netlink.U32

	// 	// filter := &netlink.U32{
	// 	// 	FilterAttrs: netlink.FilterAttrs{
	// 	// 		LinkIndex: linkIndex,
	// 	// 		Parent:    qdisc.Handle,
	// 	// 		Priority:  16,
	// 	// 		Protocol:  uint16(protocol),
	// 	// 	},
	// 	// 	ClassId:    netlink.MakeHandle(1, 2),
	// 	// 	Actions: []netlink.Action{
	// 	// 		&netlink.MatchAll{
	// 	// 			ActionAttrs:  netlink.ActionAttrs{},
	// 	// 			MirredAction: netlink.TCA_EGRESS_REDIR,
	// 	// 			Ifindex:      ifbDevice.Attrs().Index,
	// 	// 		},
	// 	// 	},
	// 	}
	// 	err = netlink.FilterAdd(filter)
	// 	if err != nil {
	// 		return fmt.Errorf("add filter: %s", err)
	// 	}
	// }

	return nil
}

func time2Tick(time uint32) uint32 {
	return uint32(float64(time) * netlink.TickInUsec())
}

func buffer(rate uint64, burst uint32) uint32 {
	return time2Tick(uint32(float64(burst) * float64(netlink.TIME_UNITS_PER_SEC) / float64(rate)))
}

func limit(rate uint64, latency float64, buffer uint32) uint32 {
	return uint32(float64(rate)*latency/float64(netlink.TIME_UNITS_PER_SEC)) + buffer
}

func latencyInUsec(latencyInMillis float64) float64 {
	return float64(netlink.TIME_UNITS_PER_SEC) * (latencyInMillis / 1000.0)
}
