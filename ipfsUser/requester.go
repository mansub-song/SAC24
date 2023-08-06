package ipfsUser

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/SherLzp/goRecrypt/curve"
	"github.com/SherLzp/goRecrypt/recrypt"
	"github.com/fentec-project/gofe/abe"
	pb "github.com/mansub-song/proxyGrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const ProxyIP = "147.46.240.242"

// output -> decrypted data
func ConcurrentDecryption(attributeKey *abe.FAMEAttribKeys) {
	//target Data = FileCipherText ([]byte)

	//1. 처음에 2bytes 읽어서 famePubKeyLen을 추출
	start := 0
	end := start + 2
	famePubKeyLen := new(big.Int).SetBytes(FileCipherText[start:end]).Int64()
	// famePubKeyLen = famePubKeyLen
	//2. [2:famePubKeyLen] 까지 읽어서 famePubKey 추출
	FamePubKey := new(abe.FAMEPubKey)
	start = end
	end = start + int(famePubKeyLen)
	err := json.Unmarshal(FileCipherText[start:end], FamePubKey)
	if err != nil {
		panic(err)
	}
	//3. 3bytes 읽어서 fameCipher 추출
	start = end
	end = start + 3
	fameCipherLen := new(big.Int).SetBytes(FileCipherText[start:end]).Int64()
	//4. attributeKey를 이용해서 fameCipher을 decryption input = {famecipher,attributeKey,famePubKey}
	start = end
	end = start + int(fameCipherLen)
	fameCipher := new(abe.FAMECipher)
	err = json.Unmarshal(FileCipherText[start:end], fameCipher)
	if err != nil {
		panic(err)
	}
	secretHeader, err := pb.Fame.Decrypt(fameCipher, attributeKey, FamePubKey)
	if err != nil {
		panic(err)
	}
	//5. iv (16bytes) + string(shuffleArr) (256bytes) + AESKeys (32bytes*N) <- shuffleArr는 []byte로 표현할 것
	start = 0
	end = start + 16
	iv := secretHeader[start:end]
	start = end
	end = start + 256
	shuffleArr := []byte(secretHeader[start:end])
	start = end
	end = len(secretHeader)
	NumThread := (end - start) / 32

	aesKey := make([]string, NumThread)
	for i := 0; i < NumThread; i++ {
		aesKey[i] = secretHeader[start : start+32]
		start = start + 32
	}

	fmt.Printf("famePubKeyLen:%d  fameCipherLen:%d\n", famePubKeyLen, fameCipherLen)
	fmt.Printf("iv:%s, len(shuffleArr): %d, NumThread:%d,aesKey:%+v \n", iv, len(shuffleArr), NumThread, aesKey)
	//6. threadDecryption
	//7. return decrypted data & FileCipherText memory free

}

func GetAttributeKey() *abe.FAMEAttribKeys {
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
	//TODO: 뭔가 key를 지역변수로 쓰지말고 전역변수로 써야됨
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

	// fmt.Println("attributeKeyBytes:", attributeKeyBytes, "size:", len(attributeKeyBytes)) // okay

	// var attributeKey *abe.FAMEAttribKeys 는 안된다. 이유는 객체 생성을 안해주고 선언만 된 것이기 때문
	attributeKey := new(abe.FAMEAttribKeys)
	err = json.Unmarshal(attributeKeyBytes, attributeKey)
	if err != nil {
		panic(err)
	}
	// fmt.Println("attributeKey:", attributeKey)
	fmt.Println("func GetAttributeKey Done!")
	return attributeKey
}
