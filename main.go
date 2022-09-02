package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/holiman/uint256"
	// btc "github.com/John-Tonny/vclsuite_vcld/dcrec$GOPATH/secp256k1/v3"
)

func main() {

	// ESK1 := btc.GeneratePrivateKey()
	// curve := curves.ED25519()
	// O := curve.Point.Generator().Identity()
	// n := math.U256(big.NewInt(115792089237316195423570985008687907852837564279074904382605163141518161494337))
	str := "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
	N, _ := uint256.FromHex(str)

	fmt.Println(N.String())
	// **************** \\
	//Step 1 ECDSA keys 2 sets

	ESK_1, _ := KeyGen()

	// N := curve.elliptic
	// log.Println("ECDSA 1 keys: ", EPK_1, ESK_1)
	ESK_2, _ := KeyGen()
	// log.Println("ECDSA 1 keys: ", EPK_2, ESK_2)
	// **************** //

	// ***************** \\
	// Step 2 Pallier Key pair
	PSK, _ := GenerateKey(rand.Reader, 256)
	PPK := &PSK.PublicKey
	// ***************** \\
	// curve.Scalar.BigInt().Mod()
	// ***************** \\
	// Step 3 C1, C2, C3 = C1*C2
	// temp, _ :=
	C1, _ := Encrypt(PPK, ESK_1.Bytes()) // to_kyber.SetBytes(temp)
	C2, _ := Encrypt(PPK, ESK_2.Bytes()) //to_kyber.SetBytes(temp)
	C1_s := new(big.Int)
	C1_s.SetBytes(C1)
	C2_s := new(big.Int)
	C2_s.SetBytes(C2)
	var C3_s big.Int
	C3_s.Mul(C1_s, C2_s)

	C3 := C3_s.Bytes()
	// C4 := C1_s.MulAdd(C2_s)
	// curve.Scalar.Mul()
	// ****************** \\
	// Npq ->
	// ****************** \\
	// Step 4:  M = D(C3), ESK_M = ESK_1*ESK_2
	temp_M, _ := Decrypt(PSK, C3)
	// M, _ := curve.Scalar.SetBytes(temp_M)

	//Scalar Addition
	ESK_M := ESK_1.Add(ESK_2) //curve.Scalar().Add(ESK_1, ESK_2)

	fmt.Println("\ntemp_M: ", temp_M, "\nESK_M: ", ESK_M.Bytes())

	// t, _ := Decrypt(PSK, []byte(C1.String()))

}
