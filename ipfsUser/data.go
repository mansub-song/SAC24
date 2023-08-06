package ipfsUser

import "fmt"

var FileCipherText []byte
var FctStart int
var FctEnd int

var FilePlainText []byte

func init() {
	FileCipherText = make([]byte, 0)
	FctStart = 0
	FctEnd = 262144 //256KB
	fmt.Println("init FileCipherText")
}

func Reset() {
	FileCipherText = make([]byte, 0)
	FctStart = 0
	FctEnd = 262144 //256KB
	fmt.Println("init FileCipherText")
	FilePlainText = make([]byte, 0)
}
