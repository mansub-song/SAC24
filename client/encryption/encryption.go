package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"os"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/fentec-project/gofe/abe"
)

var numThread = 4
var count = 256 // shuffle 영역 수

func main() {

	// fileName := os.Args[1]
	fileName := "random_1M"
	plaintext, err := os.ReadFile(fileName)
	if err != nil {
		panic(err)
	}
	time.Sleep(5 * time.Second)

	shuffleArr := make([]byte, count)
	for i := 0; i < count; i++ {
		shuffleArr[i] = byte(i)
	}
	for i := 0; i < count; i++ {
		rand.Shuffle(len(shuffleArr), func(i, j int) {
			shuffleArr[i], shuffleArr[j] = shuffleArr[j], shuffleArr[i]
		})
	}

	//thread 만큼의 region을 분리해서 각 리전에 대해서 sorting
	var w sync.WaitGroup
	w.Add(numThread)
	for i := 0; i < numThread; i++ {
		go func(i int) {
			defer w.Done()
			shuffleStart := i * (count / numThread)
			shuffleEnd := (i + 1) * (count / numThread)
			ConcurentSortShuffling(shuffleArr[shuffleStart:shuffleEnd])
		}(i)
	}
	w.Wait()

	//shuffle arrary 기반으로 data shuffling
	//TODO: data shuffling없이 encryption 되도록 고쳐야 됨
	st := time.Now()
	shuffleSpace := len(plaintext) / count
	for i := 0; i < count; i++ {
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
	ciphertext := make([][]byte, numThread)
	aesKey := make([]string, numThread)
	iv := "1234567890123456"
	w.Add(numThread)
	threadSpace := len(plaintext) / numThread
	for i := 0; i < numThread; i++ {
		go func(i int) {
			defer w.Done()
			start := i * threadSpace
			end := (i + 1) * threadSpace
			aesKey[i] = "12345678901234567890123456789012"
			// shuffleStart := i * (count / numThread)
			// shuffleEnd := (i + 1) * (count / numThread)
			ciphertext[i] = ConcurrentEncryption(plaintext[start:end], aesKey[i], iv)
		}(i)
	}
	w.Wait()

	//FAME
	fame := abe.NewFAME()
	pubKey, secKey, err := fame.GenerateMasterKeys()
	if err != nil {
		log.Fatalf("Failed to generate fame keys: %v", err)
	}
	pubKeyBytes, err := json.Marshal(pubKey)
	if err != nil {
		log.Fatalf("Failed to marshal pubKeyBytes: %v", err)
	}
	secKeyBytes, err := json.Marshal(secKey)
	if err != nil {
		log.Fatalf("Failed to marshal secKeyBytes: %v", err)
	}

	fmt.Printf("Size pubKey: %d secKey: %d\n", len(pubKeyBytes), len(secKeyBytes))

	msp, err := abe.BooleanToMSP("((0 AND 1) OR (2 AND 3)) AND 5", false) // attribute가 많아질수록 시간이 오래 걸림
	if err != nil {
		log.Fatalf("Failed to generate the policy: %v", err)
	}

	header := make([]byte, 0)
	var famePubkeyLen []byte = big.NewInt(int64(len(pubKeyBytes))).Bytes()
	header = append(header, famePubkeyLen...)
	fmt.Println("after push famePubkeyLen to header:", len(header))
	header = append(header, pubKeyBytes...)
	fmt.Println("after push pubKeyBytes to header:", len(header))
	start := len(header)
	var secretHeader string
	for i := 0; i < numThread; i++ {
		secretHeader = secretHeader + aesKey[i]
	}
	secretHeader = secretHeader + string(shuffleArr) + iv
	fameCipher, err := fame.Encrypt(secretHeader, msp, pubKey)
	if err != nil {
		log.Fatalf("Failed to encrypt of fame: %v", err)
	}
	fameCipherBytes, err := json.Marshal(fameCipher)
	var fameCipherLen []byte = big.NewInt(int64(len(fameCipherBytes))).Bytes()
	if len(fameCipherLen) == 2 {
		padding := make([]byte, 0)
		padding = append(padding, byte(0))
		fameCipherLen = append(padding, fameCipherLen...)
	}
	header = append(header, fameCipherLen...)
	fmt.Println("after push fameCipherLen to header:", len(header), len(fameCipherLen))
	end := len(header)
	header = append(header, fameCipherBytes...)
	fmt.Println("after push fameCipherBytes to header:", len(header))
	var decoded_int int64 = new(big.Int).SetBytes(header[start:end]).Int64()
	fmt.Println("decoded int", decoded_int)
	decoded_int = new(big.Int).SetBytes(header[start+1 : end]).Int64()
	fmt.Println("decoded int", decoded_int)

	gamma := []string{"0", "2", "3", "5"}
	keys, err := fame.GenerateAttribKeys(gamma, secKey)
	if err != nil {
		log.Fatalf("Failed to generate keys: %v", err)
	}

	msgCheck, err := fame.Decrypt(fameCipher, keys, pubKey)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}
	fmt.Println(secretHeader)
	fmt.Println(msgCheck)
	fmt.Println(reflect.DeepEqual(secretHeader, msgCheck))

}

// src - shuffle된 배열, orgigin - 원본 배열
func checkShuffle(src []byte, origin []byte, shuffleArray []byte, space int) {
	for i := len(shuffleArray) - 1; i >= 0; i-- {
		tmp := make([]byte, space) // need fresh memory
		srcStart := i * space
		srcEnd := (i + 1) * space
		dstStart := int(shuffleArray[i]) * space
		dstEnd := (int(shuffleArray[i]) + 1) * space

		copy(tmp, src[srcStart:srcEnd])

		copy(src[srcStart:srcEnd], src[dstStart:dstEnd])

		copy(src[dstStart:dstEnd], tmp)

	}

	fmt.Println("equal:", reflect.DeepEqual(src, origin))
}

func ConcurrentEncryption(plaintext []byte, key, iv string) []byte {
	// key := "12345678901234567890123456789012"
	// iv := "1234567890123456"
	cipherText := Ase256Encode(plaintext, key, iv, aes.BlockSize)
	return cipherText
}

func ConcurrentDecryption(ciphertext []byte, key, iv string) []byte {
	// key := "12345678901234567890123456789012"
	// iv := "1234567890123456"
	recoverytext := Ase256Decode(ciphertext, key, iv)
	return recoverytext
}

func ConcurentSortShuffling(shuffleArray []byte) {
	sort.Slice(shuffleArray, func(i, j int) bool {
		return shuffleArray[i] < shuffleArray[j]
	})
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

// AES - CBC mode
func Ase256Decode(ciphertext []byte, encKey string, iv string) (recoverytext []byte) {
	bKey := []byte(encKey)
	bIV := []byte(iv)
	// cipherTextDecoded, err := hex.DecodeString(cipherText)
	// if err != nil {
	// 	panic(err)
	// }

	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}

	recoverytext = make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, bIV)
	mode.CryptBlocks(recoverytext, ciphertext)
	return PKCS5UnPadding(recoverytext)
}

func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
