package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
)

func main() {

	// Let's make it work for ipv4 first

	subnet := "172.18.42.0/24"
	// subnet := "2001:db8:abcd:1234:c000::/66"
	hostDeviceName := "bwp9fc3b44f245d"

	_, nw, err := net.ParseCIDR(subnet)
	if err != nil {
		panic("Bad cidr")
	}

	var maskArr []byte = nw.Mask
	var subnetArr []byte = nw.IP

	if len(maskArr) != len(subnetArr) {
		log.Panicf("len(mask) != len(subnet) should not happen", len(maskArr), len(subnetArr))
	}

	isIpv4 := nw.IP.To4() != nil
	protocol := syscall.ETH_P_IPV6
	var offset int32 = 24
	if isIpv4 {
		// protocol = syscall.IPPROTO_IPIP
		protocol = syscall.ETH_P_IP
		offset = 16
		maskArr = maskArr[len(maskArr)-4:]
		subnetArr = subnetArr[len(subnetArr)-4:]
	} else {
		maskArr = maskArr[len(maskArr)-16:]
		subnetArr = subnetArr[len(subnetArr)-16:]
	}

	for i, a := range maskArr {
		println(fmt.Sprintf("byte %d: %d", i, a))
	}

	// For ipv4 we should have at most 1 key, for ipv6 at most 4
	keys := make([]netlink.TcU32Key, 0)

	for i := 0; i < len(maskArr); i += 4 {
		var mask, subnet uint32
		buf := bytes.NewReader(maskArr[i : i+4])
		err = binary.Read(buf, binary.BigEndian, &mask)
		if err != nil {
			log.Panicf("Error building mask iter %d", i)
		}

		log.Printf("Mask %d\n", mask)

		if mask != 0 {
			log.Printf("Mask %d is not 0\n", mask)
			// If mask == 0, any value on this section will be a match
			buf = bytes.NewReader(subnetArr[i : i+4])
			err = binary.Read(buf, binary.BigEndian, &subnet)
			if err != nil {
				log.Panicf("Error building subnet iter %d", i)
			}

			log.Println("Subnet %d", subnet)

			keys = append(keys, netlink.TcU32Key{
				Mask:    mask,
				Val:     subnet,
				Off:     offset,
				OffMask: 0,
			})
		}

		offset += 4
	}

	if isIpv4 {
		if len(keys) > 1 {
			log.Panicf("matching rules should not be more than 1 (%d)", len(keys))
		}
	} else {
		if len(keys) > 4 {
			log.Panicf("matching rules should not be more than 4 (%d)", len(keys))
		}
	}

	hostDevice, err := netlink.LinkByName(hostDeviceName)
	if err != nil {
		panic(fmt.Errorf("get host device: %s", err))
	}

	var mask uint32
	buf := bytes.NewReader(maskArr)
	err = binary.Read(buf, binary.BigEndian, &mask)

	if err != nil {
		panic("Error mask")
	}
	var selector *netlink.TcU32Sel
	if len(keys) > 0 {
		log.Printf("Len %d\n", len(keys))
		selector = &netlink.TcU32Sel{
			// Nkeys: uint8(len(keys)),
			Flags: netlink.TC_U32_TERMINAL,
			Keys:  keys,
		}
	}

	tcFilter := netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: hostDevice.Attrs().Index,
			Parent:    netlink.MakeHandle(1, 0),
			Priority:  16,
			Protocol:  uint16(protocol),
		},
		ClassId: netlink.MakeHandle(1, 1),
		Sel:     selector,
	}

	err = netlink.FilterAdd(&tcFilter)
	if err != nil {
		println("Error creating filter")
		panic(err)
	}
}
