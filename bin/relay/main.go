package main

import (
	"crypto/ecdh"
	"encoding/hex"
	"flag"
	"fmt"
	"mtobject/sdr"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
)

var privateKeyString string
var popidString string
var addrString string
var debugAddrString string

var genKey bool

func init() {
	flag.StringVar(&popidString, "popid", "", "")
	flag.StringVar(&addrString, "addr", "", "address to use")
	flag.StringVar(&debugAddrString, "debugaddr", "", "http debug server address to use (optional)")

	flag.BoolVar(&genKey, "genkey", false, "generate a random private key")
	flag.StringVar(&privateKeyString, "privkey", "", "hex-encoded private key to use for relay_public_key in sdr config")
}

func main() {
	flag.Parse()

	if debugAddrString != "" {
		go func() {
			err := http.ListenAndServe(debugAddrString, nil)
			panic(err)
		}()
	}

	addr, err := netip.ParseAddrPort(addrString)
	if err != nil {
		fmt.Printf("couldn't decode addr: %s\n", err.Error())
		return
	}

	var privateKey *ecdh.PrivateKey

	if genKey {
		privateKey, err = ecdh.X25519().GenerateKey(nil)
		if err != nil {
			fmt.Printf("failed to generate private key: %s\n", err)
			return
		}

		fmt.Printf("private key: %x\n", privateKey.Bytes())
	} else {
		privateKeyBytes, err := hex.DecodeString(privateKeyString)
		if err != nil {
			fmt.Printf("couldn't decode private key: %s\n", err.Error())
			return
		}

		privateKey, err = ecdh.X25519().NewPrivateKey(privateKeyBytes)
		if err != nil {
			fmt.Printf("couldn't init private key: %s\n", err.Error())
			return
		}
	}

	if popidString == "" || len(popidString) > 4 {
		fmt.Println("popid cannot be empty or more than 4 characters")
		return
	}
	var popid [4]byte
	copy(popid[:], popidString)

	fmt.Printf("public key: %x\n", privateKey.PublicKey().Bytes())

	relay, err := sdr.NewRelay(popid, privateKey, addr)
	if err != nil {
		fmt.Printf("couldn't init relay: %s\n", err.Error())
		return
	}

	relay.Run()
}
