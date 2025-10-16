package crypto

import (
	crand "crypto/rand"
	"fmt"

	jubjub "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
	"github.com/stretchr/testify/require"

	"testing"
)

func TestJubjubKeyGeneration(t *testing.T) {
	// 키 생성
	priv, err := jubjub.GenerateKey(crand.Reader)
	require.NoError(t, err)

	// 공개키가 커브 위에 있는지 확인
	pubk := priv.PublicKey
	require.True(t, pubk.A.IsOnCurve(), "Generated public key is not on curve")

	fmt.Printf("Private Key (hex): %x\n", priv.Bytes())
	fmt.Printf("Public Key (compressed): %x\n", pubk.Bytes())
}

func TestECDHESharedSecret(t *testing.T) {
	// Alice의 키 생성
	alicePriv, err := jubjub.GenerateKey(crand.Reader)
	require.NoError(t, err)
	alicePub := &alicePriv.PublicKey

	// Bob의 키 생성
	bobPriv, err := jubjub.GenerateKey(crand.Reader)
	require.NoError(t, err)
	bobPub := &bobPriv.PublicKey

	// Alice가 계산한 공유키: alicePriv * bobPub
	sharedSecretAlice, err := ECDHEComputeSharedSecret(alicePriv, bobPub)
	require.NoError(t, err)

	// Bob이 계산한 공유키: bobPriv * alicePub
	sharedSecretBob, err := ECDHEComputeSharedSecret(bobPriv, alicePub)
	require.NoError(t, err)

	// 두 공유키가 같은지 확인
	require.Equal(t, sharedSecretAlice, sharedSecretBob, "Shared secrets do not match")

	// Alice's Sapling KDF
	saplingKeyAlice, err := SaplingKDF(sharedSecretAlice, 44)
	require.NoError(t, err)

	// Bob's Sapling KDF
	saplingKeyBob, err := SaplingKDF(sharedSecretBob, 44)
	require.NoError(t, err)

	require.Equal(t, saplingKeyAlice, saplingKeyBob, "sapling key do not match")

	encKey := saplingKeyAlice[:32]
	nonce := saplingKeyAlice[32:44]

	fmt.Println("\n=== ECDHE Key Exchange (gnark-crypto) ===")
	fmt.Printf("Alice's Public Key: %x\n", alicePub.Bytes())
	fmt.Printf("Bob's Public Key:   %x\n", bobPub.Bytes())
	fmt.Printf("Shared Secret:      %x\n", sharedSecretAlice)
	fmt.Printf("Sapling KDF:        %x\n", saplingKeyAlice)
	fmt.Printf("ENC Key:            %x\n", encKey)
	fmt.Printf("Nonce:              %x\n", nonce)

}

//func TestMultipleKeyExchanges(t *testing.T) {
//	// 여러 당사자 간의 키 교환 시뮬레이션
//	participants := []struct {
//		name string
//		priv *JubjubPrivateKey
//		pub  *JubjubPublicKey
//	}{}
//
//	// 3명의 참가자 생성
//	names := []string{"Alice", "Bob", "Charlie"}
//	for _, name := range names {
//		priv, pub, err := GenerateJubjubKey(rand.Reader)
//		if err != nil {
//			t.Fatalf("Failed to generate key for %s: %v", name, err)
//		}
//		participants = append(participants, struct {
//			name string
//			priv *JubjubPrivateKey
//			pub  *JubjubPublicKey
//		}{name, priv, pub})
//	}
//
//	fmt.Println("\n=== Multiple Party Key Exchange ===")
//
//	// 각 참가자가 다른 참가자들과 공유키 생성
//	for i := 0; i < len(participants); i++ {
//		for j := i + 1; j < len(participants); j++ {
//			shared1, err := ECDHEComputeSharedSecret(participants[i].priv, participants[j].pub)
//			if err != nil {
//				t.Fatalf("Failed to compute shared secret: %v", err)
//			}
//
//			shared2, err := ECDHEComputeSharedSecret(participants[j].priv, participants[i].pub)
//			if err != nil {
//				t.Fatalf("Failed to compute shared secret: %v", err)
//			}
//
//			if !shared1.Equal(shared2) {
//				t.Errorf("Shared secrets between %s and %s do not match",
//					participants[i].name, participants[j].name)
//			}
//
//			sharedBytes := shared1.Bytes()
//			fmt.Printf("%s <-> %s: %x...%x\n",
//				participants[i].name,
//				participants[j].name,
//				sharedBytes[:4],
//				sharedBytes[len(sharedBytes)-4:])
//		}
//	}
//}

func BenchmarkJubjubKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := jubjub.GenerateKey(crand.Reader)
		require.NoError(b, err)
	}
}

func BenchmarkECDHESharedSecret(b *testing.B) {
	alicePriv, err := jubjub.GenerateKey(crand.Reader)
	require.NoError(b, err)
	bobPriv, err := jubjub.GenerateKey(crand.Reader)
	require.NoError(b, err)
	bobPub := &bobPriv.PublicKey

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ECDHEComputeSharedSecret(alicePriv, bobPub)
		require.NoError(b, err)
	}
}
