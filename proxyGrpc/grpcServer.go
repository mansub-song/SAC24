package proxyGrpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	// pb "SAC24/proxyGrpc"

	"github.com/SherLzp/goRecrypt/recrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const GrpcPort = 50051
const DataOwnerIP = "147.46.240.242"
const DataOwnerPort = GrpcPort

// var priKey *ecdsa.PrivateKey
// var pubKey *ecdsa.PublicKey
// var famePubKey *abe.FAMEPubKey
// var fameSecKey *abe.FAMESecKey
// var fame *abe.FAME

// server is used to implement reapGRPC.GreeterServer.
type server struct {
	UnimplementedGreeterServer
}

// Get preferred outbound ip of this machine
func GetLocalIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// client <-> proxy
func (s *server) GetAttributeKeyCipher(ctx context.Context, in *ClientSendRequest) (*ClientReceiveReply, error) {
	// fmt.Println("aaaa?")
	cid := in.GetCid()
	cid = cid
	attributeSet := in.GetAttributeSet()
	clientPubKey := in.GetPubKey()

	//TODO: levelDB 읽어서 ip찾기

	// data owner와 연결
	conn, err := grpc.Dial(DataOwnerIP+":"+strconv.Itoa(DataOwnerPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := NewGreeterClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	//data owner와 rpc 통신
	// fmt.Println("here?????")
	dataOwnerReply, err := c.GetReEncryptionKey(ctx, &ProxyNodeSendRequest{AttributeSet: attributeSet, ClientPubKey: clientPubKey})
	if err != nil {
		log.Fatalf("Failed to GetReEncryptionKey rpc function: %v", err)
	}
	// fmt.Println("Done GetReEncryptionKey RPC")
	//
	reEncKey := dataOwnerReply.GetReEncKey()

	reEncPubKey := dataOwnerReply.GetReEncPubKey()
	cipherText := dataOwnerReply.GetCipherText()
	capsuleBytes := dataOwnerReply.GetCapsule()

	//데이터 변환
	rk := new(big.Int)
	rk, _ = rk.SetString(reEncKey, 10)
	// var capsule *recrypt.Capsule
	capsule, err := recrypt.Mssong_DecodeCapsule(capsuleBytes)
	if err != nil {
		log.Fatalf("Failed to Unmarshal: %v", err)
	}
	//re-encrypt
	newCapsule, err := recrypt.ReEncryption(rk, capsule)
	if err != nil {
		log.Fatalf("Failed to ReEncryption: %v", err)
	}

	newCapsuleBytes, _ := recrypt.Mssong_EncodeCapsule(*newCapsule)
	return &ClientReceiveReply{NewCapsule: newCapsuleBytes, ReEncPubKey: reEncPubKey, CipherText: cipherText}, nil
	// log.Printf("Greeting: %s", r.GetMessage())
}

// proxy <-> data owner
func (s *server) GetReEncryptionKey(ctx context.Context, in *ProxyNodeSendRequest) (*ProxyNodeReceiveReply, error) {
	// fmt.Println("here?????~!!_1")
	attributeSet := in.GetAttributeSet()
	attrSet := strings.Split(attributeSet, ",")

	clientPubKeyBytes := in.GetClientPubKey()
	// fmt.Printf("clientPubKeyBytes: %#v\n", clientPubKeyBytes)

	//attribute key 생성
	// fmt.Println("attrSet:", attrSet, "fameSecKey:", FameSecKey)
	attributeKey, err := Fame.GenerateAttribKeys(attrSet, FameSecKey)
	if err != nil {
		// log.Fatalf("Failed to GenerateAttribKeys: %v", err)
		panic(err)
	}
	//attribute key Encryption
	attributeKeyBytes, err := json.Marshal(attributeKey)
	if err != nil {
		// log.Fatalf("Failed to Marshal: %v", err)
		panic(err)
	}

	// fmt.Println("attributeKey:", attributeKeyBytes, len(attributeKeyBytes))
	cipherText, capsule, err := recrypt.Encrypt(string(attributeKeyBytes), PubKey)
	if err != nil {
		// log.Fatalf("Failed to Encrypt: %v", err)
		panic(err)
	}
	//re-encryption key gen
	// var clientPubKey *ecdsa.PublicKey = &ecdsa.PublicKey{}
	// err = json.Unmarshal([]byte(clientPubKeyString), clientPubKey)
	// fmt.Println("here?")
	clientPubKey_any, err := x509.ParsePKIXPublicKey(clientPubKeyBytes)
	if err != nil {
		// log.Fatalf("Failed to Unmarshal clientPubKey: %v", err)
		panic(err)
	}
	clientPubKey := clientPubKey_any.(*ecdsa.PublicKey)
	// fmt.Printf("clientPubKey:%#v\n", clientPubKey)
	rk, pubX, err := recrypt.ReKeyGen(PriKey, clientPubKey)
	if err != nil {
		// log.Fatalf("Failed to ReKeyGen: %v", err)
		panic(err)
	}

	// pubXBytes, _ := json.Marshal(pubX)
	pubXBytes, err := x509.MarshalPKIXPublicKey(pubX)
	if err != nil {
		panic(err)
	}
	capsuleBytes, err := recrypt.Mssong_EncodeCapsule(*capsule)
	if err != nil {
		panic(err)
	}
	return &ProxyNodeReceiveReply{ReEncKey: rk.String(), ReEncPubKey: pubXBytes, CipherText: cipherText, Capsule: capsuleBytes}, nil //이부분 string으로 변환
}

func ServerInit() {
	//TODO: 지워야함
	// priKey, pubKey, _ = curve.GenerateKeys()
	// fame = abe.NewFAME()
	// famePubKey, fameSecKey, _ = fame.GenerateMasterKeys()

	// ipfsUser.GenKeys()
	// fmt.Println("ipfsUser private:", len(ipfsUser.PriKey, len(ipfsUser.PubKey)))
	localIP := GetLocalIP().String()
	lis, err := net.Listen("tcp", fmt.Sprintf(localIP+":%d", GrpcPort))
	if err != nil {
		fmt.Printf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	RegisterGreeterServer(s, &server{})
	fmt.Printf("# MSSONG - GRPC server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		fmt.Printf("failed to serve: %v", err)
	}

}
