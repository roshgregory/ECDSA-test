package main

import (
	"log"
)

func main() {
	ESK_1, EPK_1 := KeyGen()
	log.Println("ECDSA 1 keys: ", EPK_1, ESK_1)
	ESK_2, EPK_2 := KeyGen()
	log.Println("ECDSA 1 keys: ", EPK_2, ESK_2)
}
