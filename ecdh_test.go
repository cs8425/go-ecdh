package ecdh

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestNIST224(t *testing.T) {
	testECDH(NewEllipticECDH(elliptic.P224()), t)
}

func TestNIST256(t *testing.T) {
	testECDH(NewEllipticECDH(elliptic.P256()), t)
}

func TestNIST384(t *testing.T) {
	testECDH(NewEllipticECDH(elliptic.P384()), t)
}

func TestNIST521(t *testing.T) {
	testECDH(NewEllipticECDH(elliptic.P521()), t)
}

func BenchmarkNIST224(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testECDH(NewEllipticECDH(elliptic.P224()), b)
	}
}

func BenchmarkNIST256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testECDH(NewEllipticECDH(elliptic.P256()), b)
	}
}

func BenchmarkNIST384(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testECDH(NewEllipticECDH(elliptic.P384()), b)
	}
}

func BenchmarkNIST521(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testECDH(NewEllipticECDH(elliptic.P521()), b)
	}
}

func testECDH(e ECDH, t testing.TB) {
	var privKey1, privKey2 crypto.PrivateKey
	var pubKey1, pubKey2 crypto.PublicKey
	var pubKey1Buf, pubKey2Buf []byte
	var err error
	var ok bool
	var secret1, secret2 []byte

	privKey1, pubKey1, err = e.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}
	privKey2, pubKey2, err = e.GenerateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}

	pubKey1Buf = e.Marshal(pubKey1)
	pubKey2Buf = e.Marshal(pubKey2)

	UpubKey1, ok := e.Unmarshal(pubKey1Buf)
	if !ok {
		t.Fatalf("Unmarshal does not work")
	}

	pubKey1Buf2 := e.Marshal(UpubKey1)
	if !bytes.Equal(pubKey1Buf, pubKey1Buf2) {
		t.Fatalf("Marshal, Unmarshal: %d, %d do not match", pubKey1Buf, pubKey1Buf2)
	}

	UpubKey2, ok := e.Unmarshal(pubKey2Buf)
	if !ok {
		t.Fatalf("Unmarshal does not work")
	}

	pubKey2Buf2 := e.Marshal(UpubKey2)
	if !bytes.Equal(pubKey2Buf, pubKey2Buf2) {
		t.Fatalf("Marshal, Unmarshal: %d, %d do not match", pubKey2Buf, pubKey2Buf2)
	}


	secret1, err = e.GenerateSharedSecret(privKey1, UpubKey2)
	if err != nil {
		t.Error(err)
	}
	secret2, err = e.GenerateSharedSecret(privKey2, UpubKey1)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(secret1, secret2) {
		t.Fatalf("The two shared keys: %d, %d do not match", secret1, secret2)
	}
}
