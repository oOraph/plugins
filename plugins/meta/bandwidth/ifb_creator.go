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
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/plugins/pkg/ip"
)

const latencyInMillis = 25
const UncappedRate = 100_000_000_000
const DefaultClassMinorID = 48

func CreateIfb(ifbDeviceName string, mtu int, qlen int) error {

	if qlen < 1000 {
		qlen = 1000
	}

	err := netlink.LinkAdd(&netlink.Ifb{
		LinkAttrs: netlink.LinkAttrs{
			Name:   ifbDeviceName,
			Flags:  net.FlagUp,
			MTU:    mtu,
			TxQLen: qlen,
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
	hostDevice, err := netlink.LinkByName(hostDeviceName)
	if err != nil {
		return fmt.Errorf("get host device: %s", err)
	}
	return createHTB(rateInBits, burstInBits, hostDevice.Attrs().Index, excludeSubnets)
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
	err = createHTB(rateInBits, burstInBits, ifbDevice.Attrs().Index, excludeSubnets)
	if err != nil {
		// egress from the container/netns pov = ingress from the main netns/host pov
		return fmt.Errorf("create htb container egress qos rules: %s", err)
	}
	return nil
}

func createHTB(rateInBits, burstInBits uint64, linkIndex int, excludeSubnets []string) error {

	// Netlink struct fields are not clear, let's use shell

	// Step 1 qdisc
	// cmd := exec.Command("/usr/sbin/tc", "qdisc", "add", "dev", interfaceName, "root", "handle", "1:", "htb", "default", "30")
	qdisc := &netlink.Htb{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: linkIndex,
			Handle:    netlink.MakeHandle(1, 0),
			Parent:    netlink.HANDLE_ROOT,
		},
		Defcls: DefaultClassMinorID,
		// No idea what these are so let's keep the default values from source code...
		Version:      3,
		Rate2Quantum: 10,
	}
	err := netlink.QdiscAdd(qdisc)
	if err != nil {
		return fmt.Errorf("error while creating qdisc: %s", err)
	}

	// Step 2 classes

	rateInBytes := rateInBits / 8
	burstInBytes := burstInBits / 8
	bufferInBytes := buffer(rateInBytes, uint32(burstInBytes))

	// The capped class for all but excluded subnets
	// cmd = exec.Command("/usr/sbin/tc", "class", "add", "dev", interfaceName, "parent", "1:", "classid", "1:30", "htb", "rate",
	//       fmt.Sprintf("%d", rateInBits), "burst", fmt.Sprintf("%d", burstInBits))
	defClass := &netlink.HtbClass{
		ClassAttrs: netlink.ClassAttrs{
			LinkIndex: linkIndex,
			Handle:    netlink.MakeHandle(1, DefaultClassMinorID),
			Parent:    netlink.MakeHandle(1, 0),
		},
		Rate:   rateInBytes,
		Buffer: bufferInBytes,
		// Let's set up the "burst" rate to twice the specified rate
		Ceil:    2 * rateInBytes,
		Cbuffer: 0,
	}

	err = netlink.ClassAdd(defClass)
	if err != nil {
		return fmt.Errorf("error while creating htb default class: %s", err)
	}

	// The uncapped class for the excluded subnets (I did not know how to uncap so I capped it to very high)
	// cmd = exec.Command("/usr/sbin/tc", "class", "add", "dev", interfaceName, "parent", "1:", "classid", "1:1", "htb",
	// 	"rate", "100000000000")
	bigRate := uint64(UncappedRate)
	uncappedClass := &netlink.HtbClass{
		ClassAttrs: netlink.ClassAttrs{
			LinkIndex: linkIndex,
			Handle:    netlink.MakeHandle(1, 1),
			Parent:    qdisc.Handle,
		},
		Rate: bigRate,
		Ceil: bigRate,
		// No need for any burst, the minimum buffer size in q_htb.c should be enough to handle the rate which
		// is already more than enough
	}
	err = netlink.ClassAdd(uncappedClass)
	if err != nil {
		return fmt.Errorf("error while creating htb uncapped class: %s", err)
	}

	// Now add filters to redirect excluded subnets to the class 1 instead of the default one (30)

	for _, subnet := range excludeSubnets {

		// cmd = exec.Command("/usr/sbin/tc", "filter", "add", "dev", interfaceName, "parent", "1:", "protocol", protocol,
		// "prio", "16", "u32", "match", "ip", "dst", subnet, "flowid", "1:1")

		_, nw, err := net.ParseCIDR(subnet)
		if err != nil {
			return fmt.Errorf("bad subnet %s: %s", subnet, err)
		}
		var maskBytes []byte = nw.Mask
		var subnetBytes []byte = nw.IP

		if len(maskBytes) != len(subnetBytes) {
			return fmt.Errorf("error using net lib for subnet %s len(maskBytes) != len(subnetBytes) "+
				"(%d != %d) should not happen", subnet, len(maskBytes), len(subnetBytes))
		}

		isIpv4 := nw.IP.To4() != nil
		protocol := syscall.ETH_P_IPV6
		var offset int32 = 24
		keepBytes := 16
		if isIpv4 {
			protocol = syscall.ETH_P_IP
			offset = 16
			keepBytes = 4

		}

		if len(maskBytes) < keepBytes {
			return fmt.Errorf("error with net lib, unexpected count of bytes for ipv4 mask (%d < %d)",
				len(maskBytes), keepBytes)
		}
		if len(subnetBytes) < keepBytes {
			return fmt.Errorf("error with net lib, unexpected count of bytes for ipv4 subnet (%d < %d)",
				len(subnetBytes), keepBytes)
		}
		maskBytes = maskBytes[len(maskBytes)-keepBytes:]
		subnetBytes = subnetBytes[len(subnetBytes)-keepBytes:]

		// For ipv4 we should have at most 1 key, for ipv6 at most 4
		keys := make([]netlink.TcU32Key, 0)

		for i := 0; i < len(maskBytes); i += 4 {
			var mask, subnetI uint32
			buf := bytes.NewReader(maskBytes[i : i+4])
			err = binary.Read(buf, binary.BigEndian, &mask)
			if err != nil {
				return fmt.Errorf("error, htb filter, unable to build mask match filter, iter %d for subnet %s",
					i, subnet)
			}

			if mask != 0 {
				// If mask == 0, any value on this section will be a match and we do not need a filter for this
				buf = bytes.NewReader(subnetBytes[i : i+4])
				err = binary.Read(buf, binary.BigEndian, &subnetI)
				if err != nil {
					return fmt.Errorf("error, htb filter, unable to build subnet match filter, iter %d for subnet %s",
						i, subnet)
				}
				keys = append(keys, netlink.TcU32Key{
					Mask:    mask,
					Val:     subnetI,
					Off:     offset,
					OffMask: 0,
				})
			}

			offset += 4
		}

		if isIpv4 && len(keys) > 1 {
			return fmt.Errorf("error, htb ipv4 filter, unexpected rule length (%d > 1), for subnet %s",
				len(keys), subnet)
		} else if len(keys) > 4 {
			return fmt.Errorf("error, htb ipv6 filter, unexpected rule length (%d > 4), for subnet %s",
				len(keys), subnet)
		}

		// If len(keys) == 0, it means that we want to wildcard all traffic on the non default/uncapped class
		var selector *netlink.TcU32Sel
		if len(keys) > 0 {
			selector = &netlink.TcU32Sel{
				// Nkeys: uint8(len(keys)),
				Flags: netlink.TC_U32_TERMINAL,
				Keys:  keys,
			}
		}

		tcFilter := netlink.U32{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: linkIndex,
				Parent:    qdisc.Handle,
				Priority:  16,
				Protocol:  uint16(protocol),
			},
			ClassId: uncappedClass.Handle,
			Sel:     selector,
		}

		err = netlink.FilterAdd(&tcFilter)
		if err != nil {
			return fmt.Errorf("error, unable to create htb filter, details %s", err)
		}
	}
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
