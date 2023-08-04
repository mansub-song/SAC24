package main

import (
	"fmt"
	"math/big"
)

func main() {
	// Convert int to []byte
	var int_to_encode int64 = 257
	var bytes_array []byte = big.NewInt(int_to_encode).Bytes()
	fmt.Println("bytes array", bytes_array)

	// Convert []byte to int
	var decoded_int int64 = new(big.Int).SetBytes(bytes_array).Int64()
	fmt.Println("decoded int", decoded_int)
}
