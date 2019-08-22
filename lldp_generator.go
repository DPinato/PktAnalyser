package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	// device       string = "en4"
	device       string = "en0"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
)

func main() {

	// sendLLDPFrames()

	// sendLLDPFrames_2(100000)
	sendCDPFrames(10000)

}

func sendLLDPFrames() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create a properly formed packet, just with
	// empty details. Should fill out MAC addresses,
	// IP addresses, etc.
	rawBytes := []byte{10, 20, 30}

	// This time lets fill out some information
	lldpLayer := &layers.LinkLayerDiscovery{
		// ChassisID: layers.LLDPChassisID{layers.LLDPChassisIDSubTypeMACAddr, []byte{0x00, 0x13, 0x21, 0x57, 0xca, 0x7f}},
		ChassisID: layers.LLDPChassisID{layers.LLDPChassisIDSubTypeChassisComp, []byte{0x00, 0x13, 0x21, 0x57, 0xca, 0x7f}},
		PortID:    layers.LLDPPortID{layers.LLDPPortIDSubtypePortComp, []byte{0x01}},
		TTL:       120,
	}
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x13, 0x21, 0x57, 0xca, 0x7f},
		DstMAC:       net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e},
		EthernetType: layers.EthernetTypeLinkLayerDiscovery,
	}

	// And create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		lldpLayer,
		gopacket.Payload(rawBytes),
	)

	// send packet
	outgoingPacket := buffer.Bytes()
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}
}

func sendLLDPFrames_2(count int) {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// []byte that will not change are here
	chassis_subtype := []byte{0x02, 0x07, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // change the last 6 values to the source MAC
	port_subtype := []byte{0x04, 0x04, 0x05, 0x31, 0x2f, 0x31}
	ttl := []byte{0x06, 0x02, 0x00, 0x78}
	port_description := []byte{0x08, 0x17, 0x53, 0x75, 0x6d, 0x6d, 0x69, 0x74, 0x33, 0x30, 0x30, 0x2d, 0x34, 0x38, 0x2d, 0x50, 0x6f, 0x72, 0x74, 0x20, 0x31, 0x30, 0x30, 0x31, 0x00}
	system_name := []byte{0x0a, 0x0d, 0x53, 0x75, 0x6d, 0x6d, 0x69, 0x74, 0x33, 0x30, 0x30, 0x2d, 0x34, 0x38, 0x00}
	system_description := []byte{0x0c, 0x4c, 0x53, 0x75, 0x6d, 0x6d, 0x69, 0x74, 0x33, 0x30, 0x30, 0x2d, 0x34, 0x38, 0x20, 0x2d, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x37, 0x2e, 0x34, 0x65, 0x2e, 0x31, 0x20, 0x28, 0x42, 0x75, 0x69, 0x6c, 0x64, 0x20, 0x35, 0x29, 0x20, 0x62, 0x79, 0x20, 0x52, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x30, 0x35, 0x2f, 0x32, 0x37, 0x2f, 0x30, 0x35, 0x20, 0x30, 0x34, 0x3a, 0x35, 0x33, 0x3a, 0x31, 0x31, 0x00}
	capabilities := []byte{0x0e, 0x04, 0x00, 0x14, 0x00, 0x14}
	mgmt_address := []byte{0x10, 0x0e, 0x07, 0x06, 0x00, 0x01, 0x30, 0xf9, 0xad, 0xa0, 0x02, 0x00, 0x00, 0x03, 0xe9, 0x00}

	// extra_tlv := []byte{0xfe, 0x07, 0x00, 0x12, 0x0f, 0x02, 0x07, 0x01, 0x00, 0xfe, 0x09, 0x00, 0x12, 0x0f, 0x01, 0x03, 0x6c, 0x00, 0x00, 0x10, 0xfe, 0x09, 0x00, 0x12, 0x0f, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x06, 0x00, 0x12, 0x0f, 0x04, 0x05, 0xf2, 0xfe, 0x06, 0x00, 0x80, 0xc2, 0x01, 0x01, 0xe8, 0xfe, 0x07, 0x00, 0x80, 0xc2, 0x02, 0x01, 0x00, 0x00, 0xfe, 0x17, 0x00, 0x80, 0xc2, 0x03, 0x01, 0xe8, 0x10, 0x76, 0x32, 0x2d, 0x30, 0x34, 0x38, 0x38, 0x2d, 0x30, 0x33, 0x2d, 0x30, 0x35, 0x30, 0x35, 0x00, 0xfe, 0x05, 0x00, 0x80, 0xc2, 0x04, 0x00}

	lldpdu_end := []byte{0x00, 0x00}

	for i := 0; i < count; i++ {
		srcMac := generateRandomMAC()
		fmt.Printf("%d, %s\n", i, srcMac.String())

		// ethLayer the dst/src MAC and the ethertype
		ethLayer := []byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5], 0x88, 0xcc}

		for j := 0; j < len(srcMac); j++ {
			chassis_subtype[j+3] = srcMac[j]
		}

		// combine all the fields and TLVs in a single []byte
		rawBytes := append(ethLayer, chassis_subtype...)
		rawBytes = append(rawBytes, port_subtype...)
		rawBytes = append(rawBytes, ttl...)
		rawBytes = append(rawBytes, port_description...)
		rawBytes = append(rawBytes, system_name...)
		rawBytes = append(rawBytes, system_description...)
		rawBytes = append(rawBytes, capabilities...)
		rawBytes = append(rawBytes, mgmt_address...)
		rawBytes = append(rawBytes, lldpdu_end...)

		err = handle.WritePacketData(rawBytes) // send LLDP frame
		if err != nil {
			log.Fatal(err)
		}

		// fmt.Println(rawBytes)
		time.Sleep(10 * time.Millisecond)

	}

}

func sendCDPFrames(count int) {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// []byte that will not change are here
	llc := []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00}
	version := []byte{0x02}
	ttl := []byte{0xb4}
	checksum := []byte{0x48, 0xfa} // TODO
	// device_id := []byte{0x00, 0x01, 0x00, 0x10, 0x30, 0x30, 0x31, 0x38, 0x30, 0x61, 0x62, 0x36, 0x38, 0x31, 0x30, 0x31}
	device_id := []byte{0x00, 0x01, 0x00, 0x10}
	addresses := []byte{0x00, 0x02, 0x00, 0x11, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0xcc, 0x00, 0x04, 0xac, 0x14, 0x04, 0x14}
	port_id := []byte{0x00, 0x03, 0x00, 0x0b, 0x50, 0x6f, 0x72, 0x74, 0x20, 0x32, 0x34}
	capabilities := []byte{0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08}
	software_version := []byte{0x00, 0x05, 0x00, 0x05, 0x31}
	platform := []byte{0x00, 0x06, 0x00, 0x0c, 0x4d, 0x53, 0x32, 0x32, 0x30, 0x2d, 0x32, 0x34}
	native_vlan := []byte{0x00, 0x0a, 0x00, 0x06, 0x00, 0x01}

	for i := 0; i < count; i++ {
		srcMac := generateRandomMAC()
		fmt.Printf("%d, %s\n", i, srcMac.String())

		// ethLayer the dst/src MAC and the ethertype
		ethLayer := []byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc, srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5], 0x00, 0x57}

		device_id = append(device_id, generateCDPID(srcMac)...)

		fmt.Println(device_id)
		os.Exit(0)

		// combine all the fields and TLVs in a single []byte
		rawBytes := append(ethLayer, llc...)
		rawBytes = append(rawBytes, version...)
		rawBytes = append(rawBytes, ttl...)
		rawBytes = append(rawBytes, checksum...)
		rawBytes = append(rawBytes, device_id...)
		rawBytes = append(rawBytes, addresses...)
		rawBytes = append(rawBytes, port_id...)
		rawBytes = append(rawBytes, capabilities...)
		rawBytes = append(rawBytes, software_version...)
		rawBytes = append(rawBytes, platform...)
		rawBytes = append(rawBytes, native_vlan...)

		err = handle.WritePacketData(rawBytes) // send LLDP frame
		if err != nil {
			log.Fatal(err)
		}

		// fmt.Println(rawBytes)
		time.Sleep(10 * time.Millisecond)

	}

}

func generateRandomMAC() net.HardwareAddr {
	// generate random MAC address, with a fixed OUI
	tmpOUI := []byte{0x0c, 0x8d, 0xdb}
	tmpMAC := []byte{0x00, 0x00, 0x00}

	intMAC := rand.Intn(16777216) // highest 24-bit unsigned int
	// fmt.Printf("intMAC: %d %x\n", intMAC, intMAC)
	tmpMAC[0] = byte((intMAC & 0xFF0000) >> 16)
	tmpMAC[1] = byte((intMAC & 0x00FF00) >> 8)
	tmpMAC[2] = byte((intMAC & 0x0000FF) >> 0)

	tmpOut := append(tmpOUI, tmpMAC...)
	return net.HardwareAddr(tmpOut)
}

func generateCDPID(mac []byte) []byte {
	fmt.Println(mac)

	tmpStr := ""
	for i := 0; i < len(mac); i++ {
		tmpStr += fmt.Sprintf("%x", (mac[i]&0xF0)>>4)
		tmpStr += fmt.Sprintf("%x", mac[i]&0x0F)
		fmt.Printf("%d, tmpStr: %s\n", i, tmpStr)
	}

	fmt.Printf("tmpStr: %s, length %d\n", tmpStr, len(tmpStr))

	tmpOut := []byte{}

	for i := 0; i < len(mac); i++ {
		fmt.Printf("%x ", int(tmpStr[i]))
	}

	return tmpOut
}
