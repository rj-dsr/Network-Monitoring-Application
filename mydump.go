package main
import (
    "fmt"
	"os"
	"flag"
    "github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"strings"
	"log"
	"encoding/hex"
    "time"
)

var (
    intface string
    file_name string
	str string
	bpf_filter string
	found bool // Flag to check if atleast 1 packet with required specification is found
)


func main() {

		//Getting command line inputs

		flag.StringVar(&intface, "i", "No interface provided", "your interface in promiscuous mode")
		flag.StringVar(&file_name, "r", "File not provided", "trace file")
		flag.StringVar(&str, "s", "default_string", "your payload matching string pattern")
		flag.Parse()
		bpf_filter = "nil"
		argsWithoutProg := os.Args[1:]

		
		//if there are more than one arguments - to extract the "bpf filter"
		if len(argsWithoutProg) !=0 {
			if (os.Args[len(argsWithoutProg)-1] != "-s") &&  (os.Args[len(argsWithoutProg)-1] != "-i") &&  (os.Args[len(argsWithoutProg)-1] != "-r") {
				bpf_filter = os.Args[len(argsWithoutProg)]
			}
		}

		/*

		Either opencapture or capture from trace file

		For open capture, if the network interface is unspecified,
		devices in the network is found using FindAllDevs - first NIC is captured and used 
		*/
		if file_name == "File not provided" {
			if intface == "No interface provided"{
				findDevices()
			} else {
				liveCapture()
			}
		} else { 
			readFile() 
		}

	}

	//Ascertaining default network interface when input is not given for the Network interface
	func findDevices(){
		// Find all devices
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		intface = devices[0].Name
		liveCapture()
	}

	func liveCapture(){
		var (
			device       string = intface
			snapshot_len int32  = 1024
			promiscuous  bool   = true
			err          error
			timeout      time.Duration = 1 * time.Second
			handle       *pcap.Handle
		)

		// Open device
		handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
		if err != nil {log.Fatal(err) }
		defer handle.Close()
	
		//Setting BPF Filter 
		
		if bpf_filter != "nil"{
			err = handle.SetBPFFilter(bpf_filter)
			if err != nil {
				fmt.Printf("---- Please enter BPF filter in accurate BPF syntax ----\n")
				log.Fatal(err)
			}
		}

		// Use the handle as a packet source to process all packets
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			formatPacket(packet)
		}
	}	

	func readFile(){
		var (
			handle   *pcap.Handle
			err      error
		)

		handle, err = pcap.OpenOffline(file_name)
		if err != nil { log.Fatal(err) }
		defer handle.Close()

		//Setting BPF Filter 
		if bpf_filter != "nil"{
			err = handle.SetBPFFilter(bpf_filter)
			if err != nil {
				fmt.Printf("---- Please enter BPF filter in accurate BPF syntax ----\n")
				log.Fatal(err)
			}
		}
		
	
		// Loop through packets in file
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			formatPacket(packet)
		}
		//if no packet in trace file matches with input specifications 
		if !found && file_name != "File not provided"{
			fmt.Print("No packet with given specification found in the trace file\n")
		}
	}

	func formatPacket(packet gopacket.Packet){
		var stringMatched bool = false
		var payload string = ""
		var timeTemp string = ""
		var tcpUdp bool = false; 


		//Checking if payload exists, if yes, 
		if str != "default_string"{
			applicationLayer := packet.ApplicationLayer()
			if applicationLayer != nil {
				payload = string(applicationLayer.Payload())
				
				// Search for a string inside the payload
				if strings.Contains(payload, str) {
					stringMatched = true
					//fmt.Print(payload)
				}
			}	 
		}

		//String expression found in payload/string expression not provided => keep the packet
		if (str=="default_string") || (stringMatched==true) {

			//FORMAT PACKET SPECIFICATIONS ACCORDING TO EACH LAYER

			//Timestamp
			captureInfo := packet.Metadata().CaptureInfo
			_ = captureInfo
			timeTemp = captureInfo.Timestamp.String()
			pack_len := 0
			//Prints one whole timestamp of a packet until the required field
			for i := 0; i < 26; i++ {
				fmt.Printf("%s", string(timeTemp[i]))
			}
			fmt.Print(" ");
		


			//Ethernet layer

			//decoding ether Type from packet.Data()
			data := packet.Data()
			Type := hex.EncodeToString(data[12:14])

			ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethernetLayer != nil {
				ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
				fmt.Print(ethernetPacket.SrcMAC)
				fmt.Print(" ")
				fmt.Print("->")
				fmt.Print(" ")
				fmt.Print(ethernetPacket.DstMAC)
				fmt.Print(" ")
				fmt.Print("type")
				fmt.Print(" ")
				fmt.Printf("0x%s",Type)
				fmt.Print(" ")
			}
		
			//Capturing the Packet length 
			pack_len = captureInfo.Length
			fmt.Print("len")
			fmt.Print(" ")
			fmt.Printf("%d",pack_len)
			fmt.Println();


			//Obtaining Port numbers if TCP/UDP is present
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			udpLayer := packet.Layer(layers.LayerTypeUDP)

			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)

				//UDP Layer
				if udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					fmt.Printf("%s:%d -> %s:%d ", ip.SrcIP,udp.SrcPort, ip.DstIP,udp.DstPort)
					fmt.Print(ip.Protocol)
					fmt.Printf(" ")
					tcpUdp = true
				}
				//TCP Layer
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					fmt.Printf("%s:%d -> %s:%d ", ip.SrcIP,tcp.SrcPort, ip.DstIP,tcp.DstPort)
					fmt.Print(ip.Protocol)
					fmt.Printf(" ")
					tcpUdp = true
				}
				//Other layers - no source or destination port
				if tcpUdp == false{
					fmt.Printf("%s -> %s ", ip.SrcIP, ip.DstIP)
					fmt.Print(ip.Protocol)
					fmt.Printf(" ")
				}
				
			}

			//Getting the TCP Flags from the packet
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
				if tcp.SYN {
					fmt.Printf("SYN ")
				}
				if tcp.FIN {
					fmt.Printf("FIN ")
				}
				if tcp.RST {
					fmt.Printf("RST ")
				}
				if tcp.PSH {
					fmt.Printf("PSH ")
				}
				if tcp.ACK {
					fmt.Printf("ACK ")
				}
				if tcp.URG {
					fmt.Printf("URG ")
				}
				if tcp.ECE {
					fmt.Printf("ECE ")
				}
				if tcp.CWR {
					fmt.Printf("CWR ")
				}
				if tcp.NS {
					fmt.Printf("NS")
				}
			}
			fmt.Println();

			//Printing the payload in raw form according to required specifications
			applicationLayer := packet.ApplicationLayer()
			if applicationLayer != nil {
				payload = string(applicationLayer.Payload())
				b := []byte(payload)
				fmt.Printf("%s\n", hex.Dump(b))
			}	 
			fmt.Println()

			found = true
		}
		
		
	}

