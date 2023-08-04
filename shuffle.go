// package main

// import (
// 	"fmt"
// 	"math/rand"
// 	"reflect"
// 	"time"
// )

// type Block struct {
// 	Bytes []byte
// }

// func main() {
// 	count := 256
// 	kk := make([][]byte, count)

// 	for i := 0; i < count; i++ {
// 		token := make([]byte, 4*1024*1024)
// 		rand.Read(token)
// 		kk[i] = token
// 	}

// 	st := time.Now()
// 	arr := make([]Block, count)
// 	for i := 0; i < count; i++ {
// 		arr[i].Bytes = kk[i]
// 	}
// 	for i := 0; i < count; i++ {
// 		rand.Shuffle(len(arr), func(i, j int) {
// 			arr[i], arr[j] = arr[j], arr[i]
// 		})
// 	}
// 	elap := time.Since(st)
// 	fmt.Println("elap:", elap)

// 	for i := 0; i < count; i++ {
// 		// if kk[i] == arr[i].Bytes {
// 		// 	fmt.Println("same:", i)
// 		// } else {
// 		// 	fmt.Println("     diff:", i)
// 		// }
// 		fmt.Println("equal:", i, reflect.DeepEqual(kk[i], arr[i].Bytes))
// 	}

// 	// fmt.Println(arr)

// 	// a := 256
// 	// fmt.Printf("%X\n", a)
// }
