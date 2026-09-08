package main

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"mtobject/sdr"
	"mtobject/sdr/gen/protos"
	"net/netip"
	"os"
	"time"

	"google.golang.org/protobuf/proto"
)

// TODO: make configurable
const TicketDuration time.Duration = 3 * time.Hour

var certFile string
var gameCoordinatorLoginHex string
var authorizedClient string
var popidOverride string

// TODO: load this from the config using the popid in the routing address
var relayPublicKeyHex string

func init() {
	flag.StringVar(&certFile, "cert", "", "certificate file to sign with")
	flag.StringVar(&gameCoordinatorLoginHex, "gc", "", "hex-encoded game coordinator logon blob")
	flag.StringVar(&authorizedClient, "client", "", "client identity")
	flag.StringVar(&relayPublicKeyHex, "pubkey", "", "hex-encoded relay public key")
	flag.StringVar(&popidOverride, "popid", "", "popid override")
}

func main() {
	flag.Parse()

	if certFile == "" {
		fmt.Println("no cert file provided")
		return
	}
	if gameCoordinatorLoginHex == "" {
		fmt.Println("no gc login provided")
		return
	}
	if authorizedClient == "" {
		fmt.Println("no authorized client provided")
		return
	}
	if relayPublicKeyHex == "" {
		fmt.Println("no relay pubkey provided")
		return
	}

	if len(popidOverride) > 4 {
		fmt.Println("popid override too long")
		return
	}

	relayPublicKeyRaw, err := hex.DecodeString(relayPublicKeyHex)
	if err != nil {
		fmt.Println("bad relay public key")
		return
	}

	relayPublicKey, err := ecdh.X25519().NewPublicKey(relayPublicKeyRaw)
	if err != nil {
		fmt.Printf("bad relay public key: %s\n", err.Error())
		return
	}

	gameCoordinatorLoginBytes, err := hex.DecodeString(gameCoordinatorLoginHex)
	if err != nil {
		fmt.Println("bad gc login hex")
		return
	}

	var gameCoordinatorLoginOuter protos.CMsgSteamDatagramSignedGameCoordinatorServerLogin
	if err := proto.Unmarshal(gameCoordinatorLoginBytes, &gameCoordinatorLoginOuter); err != nil {
		fmt.Println("bad outer gc login proto")
		return
	}

	var gameCoordinatorLogin protos.CMsgSteamDatagramGameCoordinatorServerLogin
	if err := proto.Unmarshal(gameCoordinatorLoginOuter.GetLogin(), &gameCoordinatorLogin); err != nil {
		fmt.Println("bad gc login proto")
		return
	}

	signedCertBytes, err := os.ReadFile(certFile)
	if err != nil {
		fmt.Println("couldn't load cert file")
		return
	}

	var signedCert protos.CMsgSteamDatagramCertificateSigned
	if err := proto.Unmarshal(signedCertBytes, &signedCert); err != nil {
		fmt.Println("bad cert")
		return
	}

	var privateKey ed25519.PrivateKey = make([]byte, 64)
	// steam stores the private key last, but go stores it first
	copy(privateKey[0:32], signedCert.GetPrivateKeyData()[32:])
	copy(privateKey[32:64], signedCert.GetPrivateKeyData()[0:32])

	rawRoutingAddressPlaintext := gameCoordinatorLogin.GetRouting()
	if rawRoutingAddressPlaintext[4] != 3 {
		fmt.Println("routing address not plaintext")
		return
	}

	var routingAddressPlaintext protos.CMsgSteamDatagramHostedServerAddressPlaintext
	if err := proto.Unmarshal(rawRoutingAddressPlaintext[5:], &routingAddressPlaintext); err != nil {
		fmt.Println("bad routing address proto")
		return
	}

	var popid [4]byte
	if popidOverride == "" {
		copy(popid[:], rawRoutingAddressPlaintext[:4])
	} else {
		copy(popid[:], popidOverride)
	}

	encryptedRoutingAddress, err := sdr.EncryptRoutingAddress(
		&routingAddressPlaintext,
		popid,
		0, // we can't sign with CA certificates, since we don't have them!
		authorizedClient,
		gameCoordinatorLogin.GetIdentityString(),
		relayPublicKey,
	)
	if err != nil {
		fmt.Printf("failed to encrypt routing address: %s\n", err.Error())
		return
	}

	var ticketInner protos.CMsgSteamDatagramRelayAuthTicket
	// FIXME: should we really be using time.Now()
	ticketInner.SetTimeExpiry(uint32(time.Now().Add(TicketDuration).Unix()))
	ticketInner.SetAppId(gameCoordinatorLogin.GetAppid())
	ticketInner.SetAuthorizedClientIdentityString(authorizedClient)
	ticketInner.SetGameserverIdentityString(gameCoordinatorLogin.GetIdentityString())
	ticketInner.SetGameserverAddress(encryptedRoutingAddress)

	encodedTicketInner, err := proto.Marshal(&ticketInner)
	if err != nil {
		fmt.Printf("failed to encode inner ticket: %s\n", err.Error())
		return
	}

	signature, err := privateKey.Sign(nil, encodedTicketInner, crypto.Hash(0))
	if err != nil {
		fmt.Printf("failed to sign inner ticket: %s\n", err.Error())
		return
	}

	var ticket protos.CMsgSteamDatagramSignedRelayAuthTicket
	ticket.SetTicket(encodedTicketInner)
	ticket.SetCerts([]*protos.CMsgSteamDatagramCertificateSigned{&signedCert})
	ticket.SetSignature(signature)

	encodedTicket, err := proto.Marshal(&ticket)
	if err != nil {
		fmt.Printf("failed to encode ticket: %s\n", err.Error())
		return
	}

	fmt.Printf("AppID: %d\n", gameCoordinatorLogin.GetAppid())
	fmt.Printf("Server Identity: %s\n", gameCoordinatorLogin.GetIdentityString())
	fmt.Printf("PoP: %s\n", string(popid[:]))
	fmt.Printf("Routing Secret: %d\n", routingAddressPlaintext.GetRoutingSecret())
	fmt.Printf("Protocol Version: %d\n", routingAddressPlaintext.GetProtocolVersion())
	if routingAddressPlaintext.HasIpv4() {
		var rawIP [4]byte
		binary.BigEndian.PutUint32(rawIP[:], routingAddressPlaintext.GetIpv4())
		ip := netip.AddrFrom4(rawIP)
		ipPort := netip.AddrPortFrom(ip, uint16(routingAddressPlaintext.GetPort()))
		fmt.Printf("IPv4: %s\n", ipPort)
	}
	if routingAddressPlaintext.HasIpv6() {
		ip := netip.AddrFrom16([16]byte(routingAddressPlaintext.GetIpv6()))
		ipPort := netip.AddrPortFrom(ip, uint16(routingAddressPlaintext.GetPort()))
		fmt.Printf("IPv6: %s\n", ipPort)
	}
	fmt.Printf("Ticket: %s\n", base64.StdEncoding.EncodeToString(encodedTicket))
}
