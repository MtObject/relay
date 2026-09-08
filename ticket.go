package sdr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"mtobject/sdr/gen/protos"

	"google.golang.org/protobuf/proto"
)

// Unencrypted header for encrypted routing addresses
type routingAddressHeader struct {
	PopIDBytes           [4]uint8 // Unpacked PoPID of the server datacenter
	Version2             uint8    // Always 2
	RelayPubKeyFirstByte uint8    // First byte of the relay's public key
	X25519PubKey         [32]byte // DH key for deriving the decryption key
}

type Ticket struct {
	CaKeyID        uint64
	ClientIdentity string
	ServerIdentity string
	RoutingAddress []byte
}

type routingAddressAesCtx struct {
	aes   cipher.AEAD
	nonce [12]byte
}

func createRoutingAddressAesCtx(
	caKeyID uint64,
	clientIdentity string,
	serverIdentity string,
	publicKey *ecdh.PublicKey,
	privateKey *ecdh.PrivateKey,
) (routingAddressAesCtx, error) {
	secret, err := privateKey.ECDH(publicKey)
	if err != nil {
		return routingAddressAesCtx{}, err
	}

	shaCtxInner := sha256.New()
	_, _ = shaCtxInner.Write(secret)
	hashedSecret := shaCtxInner.Sum(nil)

	shaCtxOuter := sha256.New()
	_, _ = shaCtxOuter.Write(hashedSecret)
	_, _ = shaCtxOuter.Write([]byte(clientIdentity))
	_, _ = shaCtxOuter.Write([]byte(serverIdentity))

	aesCtx, err := aes.NewCipher(shaCtxOuter.Sum(nil))
	if err != nil {
		return routingAddressAesCtx{}, err
	}
	cryptCtx, err := cipher.NewGCM(aesCtx)
	if err != nil {
		return routingAddressAesCtx{}, err
	}

	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[:], caKeyID)

	return routingAddressAesCtx{
		aes:   cryptCtx,
		nonce: nonce,
	}, nil
}

func (ctx *routingAddressAesCtx) Decrypt(ciphertext []byte) ([]byte, error) {
	return ctx.aes.Open(ciphertext[:0], ctx.nonce[:], ciphertext, nil)
}

func (ctx *routingAddressAesCtx) Encrypt(plaintext []byte) []byte {
	return ctx.aes.Seal(plaintext[:0], ctx.nonce[:], plaintext, nil)
}

func DecryptRoutingAddress(
	address []byte,
	caKeyID uint64,
	clientIdentity string,
	serverIdentity string,
	privateKey *ecdh.PrivateKey,
) (*protos.CMsgSteamDatagramHostedServerAddressPlaintext, error) {
	var header routingAddressHeader
	n, err := binary.Decode(address, binary.LittleEndian, &header)
	if err != nil {
		return nil, err
	}
	ciphertext := address[n:]

	if header.Version2 != 2 {
		return nil, fmt.Errorf("bad routing address header version: %d", header.Version2)
	}

	if privateKey.PublicKey().Bytes()[0] != header.RelayPubKeyFirstByte {
		return nil, fmt.Errorf("mismatched routing address public key (prefix %x)", header.RelayPubKeyFirstByte)
	}

	publicKey, err := ecdh.X25519().NewPublicKey(header.X25519PubKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	ctx, err := createRoutingAddressAesCtx(caKeyID, clientIdentity, serverIdentity, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes ctx: %w", err)
	}

	plaintext, err := ctx.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	plainMsg := new(protos.CMsgSteamDatagramHostedServerAddressPlaintext)
	if err := proto.Unmarshal(plaintext, plainMsg); err != nil {
		return nil, fmt.Errorf("failed to deserialize plaintext: %w", err)
	}

	return plainMsg, nil
}

func EncryptRoutingAddress(
	address *protos.CMsgSteamDatagramHostedServerAddressPlaintext,
	popid [4]byte,
	caKeyID uint64,
	clientIdentity string,
	serverIdentity string,
	publicKey *ecdh.PublicKey,
) ([]byte, error) {
	ephemeralPrivateKey, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	ctx, err := createRoutingAddressAesCtx(caKeyID, clientIdentity, serverIdentity, publicKey, ephemeralPrivateKey)
	if err != nil {
		return nil, err
	}

	encodedAddress, err := proto.Marshal(address)
	if err != nil {
		return nil, err
	}

	encryptedAddress := ctx.Encrypt(encodedAddress)

	header := routingAddressHeader{
		PopIDBytes:           popid,
		Version2:             2,
		RelayPubKeyFirstByte: publicKey.Bytes()[0],
		X25519PubKey:         [32]byte(ephemeralPrivateKey.PublicKey().Bytes()),
	}

	encodedHeader, err := binary.Append(nil, binary.LittleEndian, header)
	if err != nil {
		return nil, err
	}

	return append(encodedHeader, encryptedAddress...), nil
}

func ParseTicket(ticket []byte) (Ticket, error) {
	// TODO: validate
	var msgOuter protos.CMsgSteamDatagramSignedRelayAuthTicket
	if err := proto.Unmarshal(ticket, &msgOuter); err != nil {
		return Ticket{}, err
	}

	var msgInner protos.CMsgSteamDatagramRelayAuthTicket
	if err := proto.Unmarshal(msgOuter.GetTicket(), &msgInner); err != nil {
		return Ticket{}, err
	}

	return Ticket{
		CaKeyID:        msgOuter.GetKeyId(),
		ClientIdentity: msgInner.GetAuthorizedClientIdentityString(),
		ServerIdentity: msgInner.GetGameserverIdentityString(),
		RoutingAddress: msgInner.GetGameserverAddress(),
	}, nil
}
