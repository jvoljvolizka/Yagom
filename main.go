package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/akamensky/argparse"
	yagom "github.com/jvoljvolizka/Yagom/src"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	netst "github.com/shirou/gopsutil/net"
)

const (
	debug = true //debug switch
)

//struct for keeping and sending aes key
type aesKey struct {
	password string
	salt     []byte
}

//struct for gathered info
type infobundle struct {
	//memory info
	MemTotal    uint64  `json:"totmem"`
	MemFree     uint64  `json:"freemem"`
	MemUsed     uint64  `json:"usedmem"`
	MemUsedPerc float64 `json:"usedmemperc"`
	//storage info only one part for now
	StoreTotal    uint64  `json:"totstore"`
	StoreFree     uint64  `json:"freestore"`
	StoreUsed     uint64  `json:"usedstore"`
	StoreUsedPerc float64 `json:"usedstoreperc"`
	//CPU info
	CPUVendor  string    `json:"cpuvendor"`
	CPUFamily  string    `json:"cpufamily"`
	CPUCoreNum int32     `json:"cpucorenum"`
	CPUModel   string    `json:"cpumodel"`
	CPUSpeed   float64   `json:"cpuspeed"`
	CPUPercent []float64 `json:"cpupercent"`
	//Host info
	HostOs      string `json:"hostos"`
	HostDistro  string `json:"hostdist"`
	HostID      string `json:"hostid"`
	HostName    string `json:"hostname"`
	HostUptime  uint64 `json:"hostuptime"`
	HostProcNum uint64 `json:"hostprocnum"`
	//network info needs more work
	NetInts []interInfo `json:"netinters"`
}

type interInfo struct {
	NetIntName  string   `json:"netintname"`
	NetIntMac   string   `json:"netintmac"`
	NetIntFlags []string `json:"netintflags"`
	NetIntAddr  []string `json:"netintaddr"`
}

func main() {
	// Create new parser object
	parser := argparse.NewParser("Yet another golang server monitor", "this is stupid")
	// Create flags

	clientmode := parser.Flag("c", "client", &argparse.Options{Required: false, Help: "Start as client"})
	hostip := parser.String("i", "ip", &argparse.Options{Required: true, Help: "Host ip"})
	port := parser.String("p", "port", &argparse.Options{Required: true, Help: "Connection port"})
	//key := parser.String("f", "keyfile", &argparse.Options{Required: false, Help: "Use ssh key (public for servermode private for clientmode)"})
	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		if !debug {
			os.Exit(1) //don't exit on debug
		}
	}
	//assign host and ip
	ConnHost := *hostip
	ConnPort := *port
	if debug && ConnHost == "" {

		ConnHost = "127.0.0.1" //*hostip
		ConnPort = "4200"      //*port
	}

	// Listen for incoming connections.
	if *clientmode {
		client(ConnHost, ConnPort)
	} else {
		server(ConnHost, ConnPort)
	}

}

func server(ConnHost, ConnPort string) {
	l, err := net.Listen("tcp", ConnHost+":"+ConnPort)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	// Close the listener when the application closes.
	defer l.Close()
	fmt.Println("Listening on " + ConnHost + ":" + ConnPort)
	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go serverreq(conn)

	}
}

// Handles incoming requests.
func serverreq(conn net.Conn) {

	exPublicKey := ""
	for {
		defer conn.Close()
		// Make a buffer to hold incoming data.
		buf := make([]byte, 1024)
		// Read the incoming connection into the buffer.
		len, err := conn.Read(buf)
		if err != nil {
			if err.Error() == "EOF" {
				fmt.Println(conn.RemoteAddr().String() + " closed the connection")
				conn.Close()
				return
			}
			fmt.Println("Error reading:", err.Error())
		}

		message := string(buf[:len])
		if len > 8 && message[:8] == "dalyarak" {
			if message[8:] != "" { //init handshake and update the public key
				exPublicKey = message[8:]
				pubkey, err := yagom.ParseRsaPublicKeyFromPemStr(exPublicKey)

				if err != nil {
					fmt.Println("pubkey error: ", err.Error())
					return
				}

				var key aesKey
				key.password, key.salt = yagom.CreatePass()
				packet := key.password + string(key.salt)

				if err != nil {
					panic(err)
				}
				if debug {
					fmt.Println(exPublicKey)
					fmt.Println(key.salt)
					fmt.Println(packet)
				}

				encPacket := yagom.RsaEncrypt(pubkey, []byte(packet), "")

				conn.Write(encPacket)

				for {
					buf = make([]byte, 1024)
					len, err := conn.Read(buf)
					if err != nil {
						if err.Error() == "EOF" {
							fmt.Println(conn.RemoteAddr().String() + " closed the connection")
							conn.Close()
							return
						}
						fmt.Println("Error reading:", err.Error())
					}
					message = string(buf[:len])
					if message == "dalyarak" {
						conn.Write(yagom.Encrypt([]byte(listendata()), key.password, key.salt))
					}

				}

			}

		}

	}
}

func client(ConnHost, ConnPort string) {

	// Connect to the server.
	c, err := net.Dial("tcp", ConnHost+":"+ConnPort)
	if err != nil {
		fmt.Println("Connection Error:", err.Error())
		os.Exit(1)
	}

	// Close the connection when the application closes.
	defer c.Close()

	//send pubkey for aes key exchange
	/*handshake:
	* client -> dalyarak + pubkey -> server
	* client <- dalyarak + encryptedAESkey <- server
	******* handshake completed now client can send monitor request with just dalyarak command
	* client -> dalyarak -> server
	* client <- encrypted monitor info <- server
	* Why dalyarak ? because why not ?
	**/
	keyStr := "dalyarak"
	//use minimum 2048 for rsa
	privkey, pubkey := yagom.GenerateRsaKeyPair(2048)

	exClientPub, err := yagom.ExportRsaPublicKeyAsPemStr(pubkey)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	keyStr += exClientPub

	_, err = c.Write([]byte(keyStr))

	if err != nil {
		println("Write to server failed:", err.Error())
		os.Exit(1)
	}

	buf := make([]byte, 1024)

	len, _ := c.Read(buf)

	aesKeys := yagom.RsaDecrypt(privkey, buf[:len], "")
	var keyStore aesKey
	keyStore.password = string(aesKeys[:88])
	keyStore.salt = aesKeys[88:]

	if debug {
		fmt.Println(aesKeys[88:])
		fmt.Println(string(aesKeys[:88]))
	}
	//yagom.CpuDraw()
	for {
		time.Sleep(1 * time.Second)
		c.Write([]byte("dalyarak"))
		buf = make([]byte, 2048)
		len, err = c.Read(buf)
		if err != nil {
			fmt.Println("read error : ", err)
			return
		}
		if debug {
			fmt.Println(string(yagom.Decrypt(buf[:len], keyStore.password, keyStore.salt)))
		}

	}
}

//this is the funtion that actually does the monitoring job
func listendata() string {

	var info infobundle

	vmStat, err := mem.VirtualMemory()
	if err != nil {
		fmt.Println("datalisten error : ", err)
	}

	// disk - start from "/" mount point for Linux
	// might have to change for Windows!!
	// don't have a Window to test this out, if detect OS == windows
	// then use "\" instead of "/"

	diskStat, err := disk.Usage("/")
	if err != nil {
		fmt.Println("datalisten error : ", err)
	}

	// cpu - get CPU number of cores and speed
	cpuStat, err := cpu.Info()
	if err != nil {
		fmt.Println("datalisten error : ", err)
	}
	percentage, err := cpu.Percent(0, true)
	if err != nil {
		fmt.Println("datalisten error : ", err)
	}

	// host or machine kernel, uptime, platform Info
	hostStat, err := host.Info()
	if err != nil {
		fmt.Println("datalisten error : ", err)
	}

	// get interfaces MAC/hardware address
	interfStat, err := netst.Interfaces()
	if err != nil {
		fmt.Println("datalisten error : ", err)
	}

	intnum := len(interfStat)

	info.NetInts = make([]interInfo, intnum)
	for ind, interf := range interfStat {
		info.NetInts[ind].NetIntName = interf.Name
		info.NetInts[ind].NetIntMac = interf.HardwareAddr
		info.NetInts[ind].NetIntFlags = interf.Flags

		for _, addr := range interf.Addrs {
			info.NetInts[ind].NetIntAddr = append(info.NetInts[ind].NetIntAddr, addr.String())

		}

	}

	//populate struct

	info.MemTotal = vmStat.Total
	info.MemFree = vmStat.Free
	info.MemUsed = vmStat.Used
	info.MemUsedPerc = vmStat.UsedPercent

	info.StoreTotal = diskStat.Total
	info.StoreFree = diskStat.Free
	info.StoreUsed = diskStat.Used
	info.StoreUsedPerc = diskStat.UsedPercent

	info.CPUVendor = cpuStat[0].VendorID
	info.CPUFamily = cpuStat[0].Family
	info.CPUCoreNum = cpuStat[0].Cores
	info.CPUModel = cpuStat[0].ModelName
	info.CPUSpeed = cpuStat[0].Mhz
	info.CPUPercent = percentage

	info.HostID = hostStat.HostID
	info.HostDistro = hostStat.Platform
	info.HostOs = hostStat.OS
	info.HostName = hostStat.Hostname
	info.HostUptime = hostStat.Uptime
	info.HostProcNum = hostStat.Procs

	jsondata, _ := json.Marshal(info)
	if debug {
		//fmt.Println(string(jsondata))
	}

	return string(jsondata)
}
