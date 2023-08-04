package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/fentec-project/gofe/abe"
)

var numThread = 4
var count = 256 // shuffle 영역 수

func main() {
	// plaintext := "abcdefghijklmnopqrstuvwxyzABCDEF"
	plaintext, err := ioutil.ReadFile("random_1M")
	srcPlaintext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		srcPlaintext[i] = plaintext[i]
	}

	if err != nil {
		panic(err)
	}
	// fmt.Println("Data to encode: ", len(plaintext))

	arr := make([]byte, count)
	for i := 0; i < count; i++ {
		arr[i] = byte(i)
	}
	for i := 0; i < count; i++ {
		rand.Shuffle(len(arr), func(i, j int) {
			arr[i], arr[j] = arr[j], arr[i]
		})
	}
	// fmt.Println("arr:", arr)

	var w sync.WaitGroup
	w.Add(numThread)
	for i := 0; i < numThread; i++ {
		go func(i int) {
			defer w.Done()
			shuffleStart := i * (count / numThread)
			shuffleEnd := (i + 1) * (count / numThread)
			ConcurentSortShuffling(arr[shuffleStart:shuffleEnd])
		}(i)
	}
	w.Wait()

	st := time.Now()
	shuffleSpace := len(plaintext) / count
	for i := 0; i < count; i++ {
		tmp := make([]byte, shuffleSpace) // need fresh memory
		srcStart := i * shuffleSpace
		srcEnd := (i + 1) * shuffleSpace
		dstStart := int(arr[i]) * shuffleSpace
		dstEnd := (int(arr[i]) + 1) * shuffleSpace
		copy(tmp, plaintext[srcStart:srcEnd])

		copy(plaintext[srcStart:srcEnd], plaintext[dstStart:dstEnd])

		copy(plaintext[dstStart:dstEnd], tmp)
	}
	elap := time.Since(st)
	// fmt.Println("sort arr:", arr)
	fmt.Println("elap:", elap)
	// checkShuffle(plaintext, srcPlaintext, arr, space)

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

	//concurrent decryption
	w.Add(numThread)
	recoverytext := make([][]byte, numThread)
	for i := 0; i < numThread; i++ {
		go func(i int) {
			defer w.Done()
			// start := i * space
			// end := (i + 1) * space
			// shuffleStart := i * (count / numThread)
			// shuffleEnd := (i + 1) * (count / numThread)
			recoverytext[i] = ConcurrentDecryption(ciphertext[i], aesKey[i], iv)
		}(i)
	}
	w.Wait()
	// fmt.Println("ciphertext len:", len(ciphertext), len(ciphertext[0]), len(ciphertext)*len(ciphertext[0]))
	// fmt.Println("recoverytext len:", len(recoverytext), len(recoverytext[0]), len(recoverytext)*len(recoverytext[0]))

	result := make([]byte, 0)
	for i := 0; i < len(recoverytext); i++ {
		result = append(result, recoverytext[i]...)
	}
	fmt.Println("text equal:", reflect.DeepEqual(plaintext, result), len(srcPlaintext), len(result))

	//FAME
	fame := abe.NewFAME()
	pubKey, secKey, err := fame.GenerateMasterKeys()
	if err != nil {
		log.Fatalf("Failed to generate master keys: %v", err)
	}
	// secKey = secKey
	// fmt.Println("pubkey size:", len(pubKey), "secKey size:", len(secKey))
	pubKeyBytes, err := json.Marshal(pubKey)
	if err != nil {
		log.Fatalf("Failed to marshal pub key: %v", err)
	}
	// secKeyBytes, err := json.Marshal(secKey)
	// if err != nil {
	// 	log.Fatalf("Failed to marshal secret key: %v", err)
	// }
	// fmt.Println("pubkey size:", len(pubKeyBytes), "secKey size:", len(secKeyBytes)) //pubkey size: 3404 secKey size: 1183
	// var decodedPubKey *abe.FAMEPubKey
	// err = json.Unmarshal(pubKeyBytes, &decodedPubKey)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println("pubkey equal:", reflect.DeepEqual(pubKey, decodedPubKey))

	// msp, err := abe.BooleanToMSP("((0 AND 1) OR (2 AND 3)) AND 5 AND 6 AND 7 AND 8 AND 9 AND ((10 AND 11) OR (12 AND 13)) AND 15 AND 16 AND 17 AND 18 AND 19 AND ((20 AND 21) OR (22 AND 23)) AND 25 AND 26 AND 27 AND 28 AND 29 AND ((30 AND 31) OR (32 AND 33)) AND 35 AND 36 AND 37 AND 38 AND 39", false) // attribute가 많아질수록 시간이 오래 걸림
	msp, err := abe.BooleanToMSP("((0 AND 1) OR (2 AND 3)) AND 5", false) // attribute가 많아질수록 시간이 오래 걸림
	if err != nil {
		log.Fatalf("Failed to generate the policy: %v", err)
	}

	// msg, err := ioutil.ReadFile("random_4K")
	// st_1 := time.Now()
	// fameCipher, err := fame.Encrypt(string(msg), msp, pubKey)
	// if err != nil {
	// 	log.Fatalf("Failed to encrypt: %v", err)
	// }
	// elap_1 := time.Since(st_1)
	// fameCipherBytes, err := json.Marshal(fameCipher)
	// fmt.Println("fame cipher size:", len(fameCipherBytes)) // 20~30KB 쯤
	// fmt.Println("elap:", elap_1)

	header := make([]byte, 0)
	// famePubkeyLen := []byte(strconv.Itoa())
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
	secretHeader = secretHeader + string(arr) + iv
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
