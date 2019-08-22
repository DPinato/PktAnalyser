package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type Device struct {
	MAC net.HardwareAddr
}

type ChannelStats struct {
	ChanNum       int           // number of the WiFi channel
	FramesSeen    int           // number of frames seen on this channel
	MonitoredTime time.Duration // amount of time spent monitoring this channel
}

func main() {

	// get list of network interfaces on the system
	// devs, _ := findAllDevices()
	// for _, device := range devs {
	// 	printDevInfo(device)
	// }

	// testWiredPcap("lo0")

	listChannelStats := make([]ChannelStats, 13, 13)

	// initialise things
	initChannelStats(listChannelStats)

	// testWiredPcap()
	testWifiMonitorPcap(listChannelStats, os.Args)

}

func testWifiMonitorPcap(chStatsRef []ChannelStats, args []string) {
	// test pcap on a wireless interface in monitor mode
	pcapIface := "en0"
	var snapshotLen int32 = 65535 // consider lowering this to only grab the header
	timeout := 10 * time.Second
	packetCount := 0 // number of packets captured
	currChannel := 1 // current wireless channel being monitored
	chSwitchTimer := time.Millisecond * 5000

	takePcap := processInputArgs(args)
	// pktChan := make(chan gopacket.Packet, 1000)
	// deviceMap := make(map[string]Device)

	// open device for capturing, use an InactiveHandle for monitor mode
	inHandle, err := pcap.NewInactiveHandle(pcapIface)
	if err != nil {
		log.Fatal(err)
	}
	defer inHandle.CleanUp()
	inHandle.SetPromisc(true)
	inHandle.SetRFMon(true)
	inHandle.SetTimeout(timeout)

	handle, err := inHandle.Activate() // activate the InactiveHandle to obtain a Handle
	if err != nil {
		log.Fatal(err)
	}

	// create pcap file and pcap writer
	var w *pcapgo.Writer
	if takePcap {
		f, _ := os.Create("test.pcap")
		w = pcapgo.NewWriter(f)
		// w.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeIEEE80211Radio)
		w.WriteFileHeader(uint32(snapshotLen), handle.LinkType())
		defer f.Close()
	}

	// go processPacket(pktChan)                          // goroutine to process packets as they are seen
	// go trackDevices(pktChan, chStatsRef, &packetCount) // keep track of devices
	go showChannelStats(chStatsRef, &currChannel, &packetCount)

	// run goroutine to change channel every second
	go func() {
		prevChannel := 0
		for {
			t1 := time.Now()
			time.Sleep(chSwitchTimer)
			prevChannel = currChannel
			currChannel++
			if currChannel > 13 {
				currChannel = 1
			}
			t2 := time.Now()
			chStatsRef[prevChannel-1].MonitoredTime += t2.Sub(t1)

			changeMacOSMonitorModeChannel(currChannel, pcapIface)

		}
	}()

	// start capturing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("Started capturing WiFI frames")

	changeMacOSMonitorModeChannel(currChannel, pcapIface) // make sure airport starts on channel 1
	packetSource.NoCopy = true
	for packet := range packetSource.Packets() {
		// fmt.Println(packet)
		if takePcap {
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()) // save packet
		}
		packetCount++
		// fmt.Println(packetCount)
		// pktChan <- packet

		chStatsRef[currChannel-1].FramesSeen++

	}

	// time.Sleep(time.Second * 100)

}

// func chooseNextWifiChannel(method string, )

func showChannelStats(ref []ChannelStats, currChan *int, totalFramesSeen *int) {
	// display wifi channel statistics collected so far
	for {
		// clear the screen
		cmd := exec.Command("clear") //Linux example, its tested
		cmd.Stdout = os.Stdout
		cmd.Run()

		fmt.Printf("Current channel: %d\n", *currChan)
		fmt.Printf("Total Frames Seen: %d\n\n", *totalFramesSeen)

		// show statistics about channels
		for i := 0; i < len(ref); i++ {
			fmt.Printf("Channel %d", ref[i].ChanNum)
			fmt.Printf("\tframes: %d", ref[i].FramesSeen)
			fmt.Printf("\tmon for %s", ref[i].MonitoredTime.String())
			fmt.Printf("\n")
		}

		time.Sleep(time.Millisecond * 1000)
	}

}

func trackDevices(pktCh chan gopacket.Packet, chStatsRef []ChannelStats, total *int) {
	// track devices around this
	for {
		// tmpPkt := <-pktCh // receive from channel
		// fmt.Println(len(tmpPkt.Layers()))
		// fmt.Println(tmpPkt.Layers()[1].LayerContents())
		// fmt.Println(tmpPkt.Layers()[2].LayerContents())
		// fmt.Println(tmpPkt.Layers()[3].LayerContents())

		// if tmpPkt.Layers()[0].LayerType() == layers.LayerTypeRadioTap {
		// 	fmt.Println(tmpPkt.Layers()[0])
		//
		// }

		// if len(tmpPkt.Layers()) >= 3 {
		// 	// only process packets that have L3+ headers
		// 	fmt.Printf("\t%s\t%s\t%s\n", tmpPkt.Layers()[0].LayerType().String(), tmpPkt.Layers()[1].LayerType().String(), tmpPkt.Layers()[2].LayerType().String())
		//
		// 	if tmpPkt.Layers()[2].LayerType() == layers.LayerTypeDot11MgmtBeacon {
		// 		fmt.Println(tmpPkt)
		// 	}
		// }

		// if len(packet.Layers()) >= 3 {
		// 	// only process beacon frames
		// 	if packet.Layers()[2].LayerType() == layers.LayerTypeDot11MgmtBeacon {
		//
		// 	}
		// }
	}
}

func initChannelStats(aRef []ChannelStats) {
	for i := 0; i < len(aRef); i++ {
		aRef[i] = ChannelStats{i + 1, 0, time.Millisecond * 0}
	}
}

func changeMacOSMonitorModeChannel(wifiChan int, ifName string) bool {
	// while the interface is in monitor mode, change the wireless channel
	// this can be done by running the command "airport <if> sniff <chan>"
	// anything after the channel has changed can be blocking, as long as it does not take much time to execute
	log.Printf("Changing channel on %s to channel %d ... ", ifName, wifiChan)

	args := []string{ifName, "sniff", strconv.Itoa(wifiChan)}
	cmd := exec.Command("airport", args...)
	err := cmd.Start()
	if err != nil {
		log.Fatal("Failed to run airport sniff command\t" + err.Error())
	}

	// TODO: for some reason, killing the airport sniff process straight away does not result in a change in channel
	// this is probably the best workaround for the moment
	time.Sleep(time.Millisecond * 25)
	err = cmd.Process.Kill()
	if err != nil {
		log.Fatal("Failed to kill airport sniff process\t" + err.Error())
	}

	// remove any .cap files in /tmp, they are created by airport sniff
	out, err := removeCapFiles("/tmp/")
	if out == false {
		log.Printf("removeCapFiles() failed, err: %v", err)
	}

	log.Printf("DONE\n")
	return true
}

func removeCapFiles(dirName string) (bool, error) {
	d, err := os.Open(dirName)
	if err != nil {
		return false, err
	}
	defer d.Close()

	files, err := d.Readdir(-1)
	if err != nil {
		return false, err
	}

	// find all .cap files and remove them
	for _, file := range files {
		if file.Mode().IsRegular() {
			if filepath.Ext(file.Name()) == ".cap" {
				err := os.Remove(dirName + file.Name())
				if err != nil {
					return false, err
				}
			}
		}
	}

	return true, nil
}

func testWiredPcap(iface string) {
	// test pcap on a wired interface, i.e. Ethernet
	// declare some variables
	pcapIface := iface
	var snapshotLen int32 = 65535 // consider lowering this to only grab the header
	promiscuous := false
	timeout := 30 * time.Second
	packetCount := 0
	pktChan := make(chan gopacket.Packet, 100)

	// open device for capturing
	handle, err := pcap.OpenLive(pcapIface, snapshotLen, promiscuous, timeout)
	if err != nil {
		fmt.Printf("Error opening device %s: %v", pcapIface, err)
		log.Fatal(err)
	}
	defer handle.Close()

	// create pcap wile and pcap writer
	f, _ := os.Create("test.pcap")
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(uint32(snapshotLen), handle.LinkType())
	defer f.Close()

	go processPacket(pktChan) // goroutine to process packets as they are seen

	// start capturing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// fmt.Println(packet)
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()) // store packet in capture file
		pktChan <- packet
		packetCount++
		fmt.Printf("packetCount: %d\n", packetCount)

		// stop the capture after a number of packets
		if packetCount > 10000 {
			break
		}
	}

}

func processPacket(pktCh chan gopacket.Packet) {
	// process captured packets
	counter := 0
	// m = make(map[string]int)

	for {
		tmpPkt := <-pktCh // receive from channel
		counter++
		fmt.Printf("processPacket()\tcount %d\tlen: %d\tlayers: %d\n", counter, len(tmpPkt.Data()), len(tmpPkt.Layers()))

		if len(tmpPkt.Layers()) >= 3 {
			// only process packets that have L3+ headers
			fmt.Printf("\t%s\t%s\t%s\n", tmpPkt.Layers()[0].LayerType().String(), tmpPkt.Layers()[1].LayerType().String(), tmpPkt.Layers()[2].LayerType().String())

			if tmpPkt.Layers()[2].LayerType() == layers.LayerTypeDot11MgmtBeacon {
				fmt.Println(tmpPkt)
				os.Exit(1)
			}
		}
	}

}

func findAllDevices() (ifs []pcap.Interface, err error) {
	// find all devices and return a slice with them
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	return devices, err
}

func printDevInfo(iface pcap.Interface) {
	// debug function
	fmt.Println("\nName: ", iface.Name)
	fmt.Println("Description: ", iface.Description)
	fmt.Println("Devices addresses: ", iface.Description)
	for _, address := range iface.Addresses {
		fmt.Println("- IP address: ", address.IP)
		fmt.Println("- Subnet mask: ", address.Netmask)
	}
}

func processInputArgs(args []string) bool {
	for _, a := range args {
		if a == "--nopcap" {
			return false
		}
	}
	return true
}
