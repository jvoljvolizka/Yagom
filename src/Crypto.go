package yagom

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
	"net/http"

	"golang.org/x/crypto/pbkdf2"
)

const (
	ultrasecurepassword = true //if this is true create the salt value using turkish lira to dolar exchange rate
)

//**********RSA FUNCTIONS

//GenerateRsaKeyPair shut up vscode
func GenerateRsaKeyPair(bitsize int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, bitsize)
	return privkey, &privkey.PublicKey
}

//ExportRsaPublicKeyAsPemStr shut up vscode
func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
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

//ParseRsaPublicKeyFromPemStr shut up vscode
func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
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

//RsaEncrypt shut up vscode
func RsaEncrypt(publicKey *rsa.PublicKey, sourceText []byte, label string) (encryptedText []byte) {
	var err error
	var sha256Hash hash.Hash
	sha256Hash = sha256.New()
	if encryptedText, err = rsa.EncryptOAEP(sha256Hash, rand.Reader, publicKey, sourceText, []byte(label)); err != nil {
		log.Fatal(err)
	}
	return
}

//RsaDecrypt shut up vscode
func RsaDecrypt(privateKey *rsa.PrivateKey, encryptedText []byte, label string) (decryptedText []byte) {
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

//Encrypt shut up vscode
func Encrypt(data []byte, passphrase string, salt []byte) []byte {
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

//Decrypt  shut up vscode
func Decrypt(data []byte, passphrase string, salt []byte) []byte {
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

//CreatePass AES password and salt create
func CreatePass() (string, []byte) {
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
