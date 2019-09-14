package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/akamensky/argparse"
	"golang.org/x/crypto/pbkdf2"
)

const (
	debug               = true //debug switch
	ultrasecurepassword = true //if this is true create the salt value using turkish lira to dolar exchange rate
)

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

func rsaEncrypt(publicKey *rsa.PublicKey, sourceText []byte, label string) (encryptedText []byte) {
	var err error
	var sha256Hash hash.Hash
	sha256Hash = sha256.New()
	if encryptedText, err = rsa.EncryptOAEP(sha256Hash, rand.Reader, publicKey, sourceText, []byte(label)); err != nil {
		log.Fatal(err)
	}
	return
}

func rsaDecrypt(privateKey *rsa.PrivateKey, encryptedText []byte, label string) (decryptedText []byte) {
	var err error
	var sha256Hash hash.Hash
	sha256Hash = sha256.New()
	if decryptedText, err = rsa.DecryptOAEP(sha256Hash, rand.Reader, privateKey, encryptedText, []byte(label)); err != nil {
		log.Fatal(err)
		fmt.Println(err)
	}
	return
}

//***********RSA FUNCTIONS END

//*****AES STUFF

//i stole it from https://www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/
//but for the sake of every holy goddess of technology don't ever use md5 for aes key derivation this is just plain stupid
/*func createHash(key string) string {
	hasher := md5.New() just no
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}*/

func encrypt(data []byte, passphrase string, salt []byte) []byte {
	block, _ := aes.NewCipher(pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha1.New))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string, salt []byte) []byte {
	key := pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha1.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

//*****AES STUFF END

//AES password and salt create
func createPass() (string, []byte) {
	password := make([]byte, 64)
	salt := make([]byte, 8)
	if ultrasecurepassword {
		//things that i do for just a stupid joke
		response, err := http.Get("https://api.exchangeratesapi.io/latest?base=USD&symbols=USD,TRY")
		if err != nil {
			fmt.Println("The HTTP request failed fall back to sane salt creation", err)
			_, err := rand.Read(salt)
			if err != nil {
				fmt.Println("error:", err)
			}

		} else {
			type Tree struct {
				Value map[string]float64 `json:"rates"`
			}
			data, _ := ioutil.ReadAll(response.Body)
			fmt.Println(string(data))
			var obj Tree
			json.Unmarshal(data, &obj)
			buf := new(bytes.Buffer)

			err := binary.Write(buf, binary.LittleEndian, obj.Value["TRY"])
			if err != nil {
				fmt.Println("binary.Write failed:", err)
			}
			salt = buf.Bytes() // okay seriously this is not safe if you are actually use this code for something important set ultrasecurepassword to false
		}

	} else {
		_, err := rand.Read(salt)
		if err != nil {
			fmt.Println("error:", err)
		}
	}

	_, err := rand.Read(password)
	if err != nil {
		fmt.Println("error:", err)
	}

	return base64.StdEncoding.EncodeToString(password), salt
}

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
	//struct for keeping and sending aes key
	type aesKey struct {
		password string
		salt     []byte
	}
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
				pubkey, err := parseRsaPublicKeyFromPemStr(exPublicKey)

				if err != nil {
					fmt.Println("pubkey error: ", err.Error())
					return
				}
				fmt.Println(*pubkey)

				fmt.Println(exPublicKey)
				var key aesKey
				key.password, key.salt = createPass()
				packet, _ := json.Marshal(key)
				encpacket := rsaEncrypt(pubkey, packet, "")

				conn.Write(encpacket)
			}

		}
		fmt.Println(message)
	}
}

//this is the funtion that actually does the monitoring job
func listendata(key string) {

}

func client(ConnHost, ConnPort string) {
	type aesKey struct {
		password string
		salt     []byte
	}

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
	privkey, pubkey := generateRsaKeyPair(2048)

	exClientPub, err := exportRsaPublicKeyAsPemStr(pubkey)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	keyStr += exClientPub

	//fmt.Println(exClientPub)
	_, err = c.Write([]byte(keyStr))

	buf := make([]byte, 1024)

	len, _ := c.Read(buf)

	marshKey := rsaDecrypt(privkey, buf[:len], "")

	var key aesKey
	json.Unmarshal(marshKey, &key)

	fmt.Println(privkey)
	fmt.Println(buf[:len])
	if err != nil {
		println("Write to server failed:", err.Error())
		os.Exit(1)
	}
}
