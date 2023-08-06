package ipfsUser

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/fentec-project/gofe/abe"
	"github.com/mansub-song/proxyGrpc"
)

var NumThread = 4
var Count = 256 // shuffle 영역 수

func PrintFileCipherText() {
	// fmt.Println(FileCipherText)
	fmt.Println("size FileCipherText:", len(FileCipherText))
}

func ConcurrentEncryption(reader io.Reader) {
	plaintext := StreamToByte(reader)
	// fmt.Println("size plaintext:", len(plaintext))
	shuffleArr := make([]byte, Count)
	for i := 0; i < Count; i++ {
		shuffleArr[i] = byte(i)
	}
	for i := 0; i < Count; i++ {
		rand.Shuffle(len(shuffleArr), func(i, j int) {
			shuffleArr[i], shuffleArr[j] = shuffleArr[j], shuffleArr[i]
		})
	}

	//thread 만큼의 region을 분리해서 각 리전에 대해서 sorting
	var w sync.WaitGroup
	w.Add(NumThread)
	for i := 0; i < NumThread; i++ {
		go func(i int) {
			defer w.Done()
			shuffleStart := i * (Count / NumThread)
			shuffleEnd := (i + 1) * (Count / NumThread)
			ConcurentSortShuffling(shuffleArr[shuffleStart:shuffleEnd])
		}(i)
	}
	w.Wait()

	// fmt.Println("shuffleArr:", shuffleArr)
	//shuffle arrary 기반으로 data shuffling
	//TODO: data shuffling없이 encryption 되도록 고쳐야 됨
	st := time.Now()
	shuffleSpace := len(plaintext) / Count
	// fmt.Println("len(plaintext), count, shuffleSpace:", len(plaintext), Count, shuffleSpace)
	for i := 0; i < Count; i++ {
		tmp := make([]byte, shuffleSpace) // need fresh memory
		srcStart := i * shuffleSpace
		srcEnd := (i + 1) * shuffleSpace
		dstStart := int(shuffleArr[i]) * shuffleSpace
		dstEnd := (int(shuffleArr[i]) + 1) * shuffleSpace
		copy(tmp, plaintext[srcStart:srcEnd])

		copy(plaintext[srcStart:srcEnd], plaintext[dstStart:dstEnd])

		copy(plaintext[dstStart:dstEnd], tmp)
	}
	elap := time.Since(st)
	fmt.Println("elap:", elap)

	// fmt.Println("len plaintext", len(plaintext)) //length correct
	//concurrent encryption
	ciphertext := make([][]byte, NumThread)
	aesKey := make([]string, NumThread)
	iv := "1234567890123456"
	w.Add(NumThread)
	threadSpace := len(plaintext) / NumThread
	for i := 0; i < NumThread; i++ {
		go func(i int) {
			defer w.Done()
			start := i * threadSpace
			end := (i + 1) * threadSpace
			aesKey[i] = "12345678901234567890123456789012"
			// shuffleStart := i * (Count / NumThread)
			// shuffleEnd := (i + 1) * (Count / NumThread)
			ciphertext[i] = threadEncryption(plaintext[start:end], aesKey[i], iv)
		}(i)
	}
	w.Wait()

	// totalCiphertextSize := 0
	// for i := 0; i < NumThread; i++ {
	// fmt.Printf("size ciphertext[%d]: %d\n", i, len(ciphertext[i]))
	// 	totalCiphertextSize = totalCiphertextSize + len(ciphertext[i])
	// }
	// fmt.Println("[size totalCiphertextSize (cipherTextBody)]:", totalCiphertextSize)

	//FAME
	// fame := abe.NewFAME()
	// pubKey, secKey, err := fame.GenerateMasterKeys()
	// if err != nil {
	// 	log.Fatalf("Failed to generate fame keys: %v", err)
	// }
	pubKeyBytes, err := json.Marshal(proxyGrpc.FamePubKey)
	if err != nil {
		log.Fatalf("Failed to marshal pubKeyBytes: %v", err)
	}
	// secKeyBytes, err := json.Marshal(proxyGrpc.FameSecKey)
	// if err != nil {
	// 	log.Fatalf("Failed to marshal secKeyBytes: %v", err)
	// }

	// fmt.Printf("Size pubKey: %d secKey: %d\n", len(pubKeyBytes), len(secKeyBytes))

	msp, err := abe.BooleanToMSP("((0 AND 1) OR (2 AND 3)) AND 5", false) // attribute가 많아질수록 시간이 오래 걸림
	if err != nil {
		log.Fatalf("Failed to generate the policy: %v", err)
	}

	//header 만들기
	header := make([]byte, 0)
	var famePubkeyLen []byte = big.NewInt(int64(len(pubKeyBytes))).Bytes()
	// fmt.Println("famePubkeyLen:", famePubkeyLen)
	header = append(header, famePubkeyLen...)
	// fmt.Println("after push famePubkeyLen to header:", len(header))
	header = append(header, pubKeyBytes...)
	// fmt.Println("after push pubKeyBytes to header:", len(header))
	var secretHeader string
	// iv (16bytes) + string(shuffleArr) (256bytes) + AESKeys (32bytes*N)
	secretHeader = secretHeader + iv + string(shuffleArr)
	for i := 0; i < NumThread; i++ {
		secretHeader = secretHeader + aesKey[i]
	}
	// fmt.Printf("size secretHeader: %d, shuffleArr: %d, iv(len): %d, iv:%s \n", len(secretHeader), len(shuffleArr), len(iv), iv)

	//fame encryption
	fameCipher, err := proxyGrpc.Fame.Encrypt(secretHeader, msp, proxyGrpc.FamePubKey)
	if err != nil {
		log.Fatalf("Failed to encrypt of fame: %v", err)
	}
	fameCipherBytes, err := json.Marshal(fameCipher)
	var fameCipherLen []byte = big.NewInt(int64(len(fameCipherBytes))).Bytes()
	if len(fameCipherLen) == 2 { //fame Lenght가 커질 수 있으니 안전하게 3bytes로 만들기 위함
		padding := make([]byte, 0)
		padding = append(padding, byte(0))
		fameCipherLen = append(padding, fameCipherLen...)
	}
	header = append(header, fameCipherLen...)
	// fmt.Println("after push fameCipherLen to header:", len(header), len(fameCipherLen))
	header = append(header, fameCipherBytes...)
	// fmt.Println("after push fameCipherBytes to header:", len(header))
	fmt.Println("[size header (cipherTextHeader)]", len(header))
	FileCipherText = make([]byte, 0)
	FileCipherText = append(FileCipherText, header...)
	for i := 0; i < NumThread; i++ {
		FileCipherText = append(FileCipherText, ciphertext[i]...)
	}
	fmt.Println("[size FileCipherText (cipherTextTotal)]:", len(FileCipherText))
	//return FileCipherText
}

func StreamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.Bytes()
}

func ConcurentSortShuffling(shuffleArray []byte) {
	sort.Slice(shuffleArray, func(i, j int) bool {
		return shuffleArray[i] < shuffleArray[j]
	})
}

func threadEncryption(plaintext []byte, key, iv string) []byte {
	// key := "12345678901234567890123456789012"
	// iv := "1234567890123456"
	cipherText := Ase256Encode(plaintext, key, iv, aes.BlockSize)
	return cipherText
}

// AES - CBC mode (https://gist.github.com/awadhwana/9c95377beba61293390c5fd23a3bb1df)
func Ase256Encode(plaintext []byte, key string, iv string, blockSize int) []byte {
	bKey := []byte(key) //32 bytes
	bIV := []byte(iv)   //16 bytes
	bPlaintext := PKCS5Padding(plaintext, blockSize, len(plaintext))
	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(bPlaintext))
	mode := cipher.NewCBCEncrypter(block, bIV)
	mode.CryptBlocks(ciphertext, bPlaintext)
	// fmt.Println("len ciphertext:", len(ciphertext))
	return ciphertext
}

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
