package ipfsUser

import "fmt"

var FileCipherText []byte
var FctStart int
var FctEnd int

func init() {
	FileCipherText = make([]byte, 0)
	FctStart = 0
	FctEnd = 262144 //256KB
	fmt.Println("init FileCipherText")
}
