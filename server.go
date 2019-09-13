package main

import (
	"fmt"
	"net"
	"os"

	"github.com/akamensky/argparse"
)

const (
	debug = true //debug switch
)

var publicKey = ""

func main() {
	// Create new parser object
	parser := argparse.NewParser("Yet another golang server monitor", "this is stupid")
	// Create flags
	hostip := parser.String("i", "ip", &argparse.Options{Required: true, Help: "Host ip"})
	port := parser.String("p", "port", &argparse.Options{Required: true, Help: "Connection port"})
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
	ConnType := "tcp"
	if debug {
		ConnHost = "127.0.0.1" //*hostip
		ConnPort = "4200"      //*port
		ConnType = "tcp"
	}
	// Listen for incoming connections.
	l, err := net.Listen(ConnType, ConnHost+":"+ConnPort)
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
		go handleRequest(conn)
		if publicKey != "" {
			go listendata(publicKey)
		}

	}
}

// Handles incoming requests.
func handleRequest(conn net.Conn) {
	// Make a buffer to hold incoming data.
	buf := make([]byte, 1024)
	// Read the incoming connection into the buffer.
	len, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}

	fmt.Println(buf)
	message := string(buf[:len])
	if message[:8] == "dalyarak" {
		if message[8:] != "" { //update the public key
			publicKey = message[8:]
		}
		fmt.Println(publicKey)
		conn.Write([]byte("got it\n"))

	}
	//fmt.Println(message)
	// Close the connection when you're done with it.
	conn.Close()
}

func listendata(key string) {

}
