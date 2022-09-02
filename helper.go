package main

import (
	crand "crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func Setup() *curves.Curve {
	curve := curves.ED25519() // Choosen curve : ED25519
	path := "./Generator.json"
	G := curve.Point.Generator()

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		log.Fatalf("[-] Error Creating Generator File: %s", err)
	}

	_, err = fmt.Fprintln(file, G)
	if err != nil {
		log.Fatalf("[-] Error Writing")
	}

	fmt.Println("[+] Elgamal Setup Completed")
	return curve
}

func KeyGen() (curves.Scalar, curves.Point) { //Generates <Key_pri,KeyPub> Pair
	curve := Setup()
	G := curve.Point.Generator()
	private := curve.Scalar.Random(crand.Reader)
	public := G.Mul(private)
	path := "./PublicParameters.json"

	file, err := os.OpenFile(path, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		log.Fatalf("[-] Error Creating PublicParameters File: %s", err)
	}

	_, err = fmt.Fprintf(file, "Public Key(Hex):\n%x\n", public.ToAffineCompressed())
	if err != nil {
		log.Fatalf("[-] Error Writing")
	}

	path = "./PrivateKey.json"

	file, err = os.OpenFile(path, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		log.Fatalf("[-] Error Creating PrivateKey File: %s", err)
	}

	_, err = fmt.Fprintf(file, "Private Key(Hex):\n%x\n", private.Bytes())
	if err != nil {
		log.Fatalf("[-] Error Writing")
	}

	fmt.Println("[+] KeyGen Completed")
	return private, public
}
