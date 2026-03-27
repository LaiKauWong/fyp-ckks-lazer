package main

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/cloudflare/circl/pke/kyber/kyber512"
)

const (
	Warmup  = 50
	NTrials = 1000
)

func avgUS(start time.Time, n int) float64 {
	return float64(time.Since(start).Nanoseconds()) / float64(n) / 1000.0
}

func main() {
	pt := make([]byte, kyber512.PlaintextSize)
	seed := make([]byte, kyber512.EncryptionSeedSize)
	ct := make([]byte, kyber512.CiphertextSize)
	dec := make([]byte, kyber512.PlaintextSize)

	// fixed plaintext for reproducibility
	for i := range pt {
		pt[i] = byte(i)
	}

	// KeyGen benchmark
	for i := 0; i < Warmup; i++ {
		_, _, _ = kyber512.GenerateKey(nil)
	}

	t0 := time.Now()
	for i := 0; i < NTrials; i++ {
		_, _, _ = kyber512.GenerateKey(nil)
	}
	keygenUS := avgUS(t0, NTrials)

	// one fixed keypair for encrypt/decrypt benchmark
	pk, sk, err := kyber512.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	// Encrypt benchmark
	for i := 0; i < Warmup; i++ {
		_, _ = rand.Read(seed)
		pk.EncryptTo(ct, pt, seed)
	}

	t1 := time.Now()
	for i := 0; i < NTrials; i++ {
		_, _ = rand.Read(seed)
		pk.EncryptTo(ct, pt, seed)
	}
	encryptUS := avgUS(t1, NTrials)

	// prepare one ciphertext for decrypt benchmark
	_, _ = rand.Read(seed)
	pk.EncryptTo(ct, pt, seed)

	// Decrypt benchmark
	for i := 0; i < Warmup; i++ {
		sk.DecryptTo(dec, ct)
	}

	t2 := time.Now()
	for i := 0; i < NTrials; i++ {
		sk.DecryptTo(dec, ct)
	}
	decryptUS := avgUS(t2, NTrials)

	// correctness check
	for i := range pt {
		if pt[i] != dec[i] {
			panic("decrypt mismatch")
		}
	}

	fmt.Println("=========================================================")
	fmt.Println("CIRCL Kyber512 CPAPKE Benchmark")
	fmt.Println("=========================================================")
	fmt.Printf("Scheme                : Kyber512.CPAPKE\n")
	fmt.Printf("Plaintext size        : %d bits (%d bytes)\n", 8*len(pt), len(pt))
	fmt.Printf("Public key size       : %d bytes\n", kyber512.PublicKeySize)
	fmt.Printf("Private key size      : %d bytes\n", kyber512.PrivateKeySize)
	fmt.Printf("Ciphertext size       : %d bytes\n", kyber512.CiphertextSize)
	fmt.Printf("Encryption seed size  : %d bytes\n", kyber512.EncryptionSeedSize)
	fmt.Printf("Benchmark trials      : %d\n", NTrials)
	fmt.Printf("Warmup trials         : %d\n", Warmup)
	fmt.Println("=========================================================")
	fmt.Printf("KeyGen (ms)           : %.6f\n", keygenUS/1000.0)
	fmt.Printf("Encrypt (ms)          : %.6f\n", encryptUS/1000.0)
	fmt.Printf("Decrypt (ms)          : %.6f\n", decryptUS/1000.0)
	fmt.Println("=========================================================")
	fmt.Println()
	fmt.Println("CSV:")
	fmt.Println("scheme,msg_bits,keygen_ms,encrypt_ms,decrypt_ms,pk_bytes,sk_bytes,ct_bytes")
	fmt.Printf("circl_kyber512,%d,%.6f,%.6f,%.6f,%d,%d,%d\n",
		8*len(pt),
		keygenUS/1000.0,
		encryptUS/1000.0,
		decryptUS/1000.0,
		kyber512.PublicKeySize,
		kyber512.PrivateKeySize,
		kyber512.CiphertextSize,
	)
}
