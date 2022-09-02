package main

import (
	"crypto/rand"
	"fmt"

	"go.dedis.ch/kyber/v3/suites"
)

func main() {

	// **************** \\
	//Step 1 ECDSA keys 2 sets
	ESK_1, _ := KeyGen()
	// log.Println("ECDSA 1 keys: ", EPK_1, ESK_1)
	ESK_2, _ := KeyGen()
	// log.Println("ECDSA 1 keys: ", EPK_2, ESK_2)
	// **************** //

	// ***************** \\
	// Step 2 Pallier Key pair
	PSK, _ := GenerateKey(rand.Reader, 256)
	PPK := &PSK.PublicKey
	// ***************** \\

	// ***************** \\
	// Step 3 C1, C2, C3 = C1*C2
	suite := suites.MustFind("Ed25519")
	to_kyber := suite.Scalar() // - help convert byte [] to kyber.scalar
	temp, _ := Encrypt(PPK, ESK_1.Bytes())
	C1 := to_kyber.SetBytes(temp)
	temp, _ = Encrypt(PPK, ESK_2.Bytes())
	C2 := to_kyber.SetBytes(temp)
	C3 := suite.Scalar().Mul(C1, C2)
	// ****************** \\

	// ****************** \\
	// Step 4:  M = D(C3), ESK_M = ESK_1*ESK_2
	temp_M, _ := Decrypt(PSK, []byte(C3.String()))
	M := to_kyber.SetBytes(temp_M)
	ESK_M := suite.Scalar().Mul(to_kyber.SetBytes(ESK_1.Bytes()), to_kyber.SetBytes(ESK_2.Bytes()))
	// ****************** \\
	fmt.Println(M == ESK_M)
}
