package proxyGrpc

import (
	"crypto/ecdsa"

	"github.com/SherLzp/goRecrypt/curve"
	"github.com/fentec-project/gofe/abe"
)

var PriKey *ecdsa.PrivateKey //유저 프라이빗 키
var PubKey *ecdsa.PublicKey  //유저 퍼블릭 키

var Fame *abe.FAME
var FameSecKey *abe.FAMESecKey //FAME 프라이빗 키
var FamePubKey *abe.FAMEPubKey //FAME 퍼블릭 키

func GenKeys() {
	PriKey, PubKey, _ = curve.GenerateKeys()
	Fame = abe.NewFAME()
	FamePubKey, FameSecKey, _ = Fame.GenerateMasterKeys()
	// fmt.Println("PriKey:", PriKey)
}
