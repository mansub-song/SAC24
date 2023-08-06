package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/SherLzp/goRecrypt/curve"
	"github.com/SherLzp/goRecrypt/recrypt"
	"github.com/fentec-project/gofe/abe"
	pb "github.com/mansub-song/proxyGrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const ProxyIP = "147.46.240.242"

func main() {

	// Set up a connection to the server.
	conn, err := grpc.Dial(ProxyIP+":50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewGreeterClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cid := "QM1"
	clientPriKey, clientPubKey, err := curve.GenerateKeys()
	if err != nil {
		panic(err)
	}
	clientPriKey = clientPriKey
	clientPubKeyBytes, err := x509.MarshalPKIXPublicKey(clientPubKey)
	// clientPubKeyBytes, err := json.Marshal(clientPubKey)
	if err != nil {
		panic(err)
	}
	// fmt.Println("clientPubKeyString:", string(clientPubKeyBytes))
	// fmt.Printf("clientPubKeyString: %#v\n", string(clientPubKeyBytes))
	clientPriKeyString := string(clientPubKeyBytes)
	fmt.Println(clientPriKeyString)
	fmt.Printf("clientPubKey:%#v\n", clientPubKey)

	//AttributeSet 설정
	attributeSet := "0,2,3,5"

	//Grpc function 호출
	r, err := c.GetAttributeKeyCipher(ctx, &pb.ClientSendRequest{Cid: cid, AttributeSet: attributeSet, PubKey: clientPubKeyBytes})
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	log.Printf("Greeting: %s", r.GetNewCapsule())

	capsuleBytes := r.GetNewCapsule()
	reEncPubKeyBytes := r.GetReEncPubKey()
	cipherText := r.GetCipherText()

	capsule, err := recrypt.Mssong_DecodeCapsule(capsuleBytes)
	reEncPubKeyBytes_any, err := x509.ParsePKIXPublicKey(reEncPubKeyBytes)
	reEncPubKey := reEncPubKeyBytes_any.(*ecdsa.PublicKey)

	attributeKeyBytes, err := recrypt.Decrypt(clientPriKey, capsule, reEncPubKey, cipherText)
	if err != nil {
		fmt.Println(err)
	}

	var attributeKey *abe.FAMEAttribKeys
	err = json.Unmarshal(attributeKeyBytes, attributeKey)
	if err != nil {
		fmt.Println(err)
	}

	// fmt.Println("client plianText:", plainText, len(plainText))

}
