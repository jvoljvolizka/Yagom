package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/akamensky/argparse"
)

const (
	debug = true //debug switch
)

var exPublicKey = ""

//**********RSA FUNCTIONS

func generateRsaKeyPair(bitsize int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, bitsize)
	return privkey, &privkey.PublicKey
}

func exportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkeyBytes,
		},
	)

	return string(pubkeyPem), nil
}

func parseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}

//***********RSA FUNCTIONS END

func main() {
	// Create new parser object
	parser := argparse.NewParser("Yet another golang server monitor", "this is stupid")
	// Create flags

	clientmode := parser.Flag("c", "client", &argparse.Options{Required: false, Help: "Start as client"})
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
	if debug {
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
		/* this is wrong
		if exPublicKey != "" {
			go listendata(exPublicKey)
		}*/

	}
}

// Handles incoming requests.
func serverreq(conn net.Conn) {
	// Make a buffer to hold incoming data.
	buf := make([]byte, 1024)
	// Read the incoming connection into the buffer.
	len, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}

	//fmt.Println(buf)
	message := string(buf[:len])
	if message[:8] == "dalyarak" {
		if message[8:] != "" { //init handshake and update the public key
			exPublicKey = message[8:]
			pubkey, err := parseRsaPublicKeyFromPemStr(exPublicKey)
			if err != nil {
				fmt.Println("pubkey error: ", err.Error())
				os.Exit(1)
			}
			fmt.Println(*pubkey)
		}
		fmt.Println(exPublicKey)
		conn.Write([]byte("got it\n"))

	}
	//fmt.Println(message)
	// Close the connection when you're done with it.
	conn.Close()
}

func listendata(key string) {

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
	* client -> dalyarak + pubkey  -> server
	* client <- dalyarak + encryptedAESkey <- server
	******* handshake completed now client can send monitor request with just dalyarak command
	* client -> dalyarak -> server
	* client <- encrypted monitor info <- server
	* Why dalyarak ? because why not ?
	**/
	keyStr := "dalyarak"
	//use minimum 2048 for rsa
	_, pubkey := generateRsaKeyPair(2048)

	exppub, err := exportRsaPublicKeyAsPemStr(pubkey)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	keyStr += exppub

	fmt.Println(exppub)
	_, err = c.Write([]byte(keyStr))

	if err != nil {
		println("Write to server failed:", err.Error())
		os.Exit(1)
	}
}
