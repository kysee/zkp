# BLS12-381: Native vs Emulated Performance

## Option 1: BLS12-381 as SNARK Curve (Native)

```go
// Compile with BLS12-381 scalar field
ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
```

**Inside circuit:**
```go
// Use NATIVE BLS12-381 operations - very fast!
// But this would require native BLS12-381 std library
// Which doesn't exist in gnark yet
```

**Pros:**
- ✅ Very fast BLS operations (native field arithmetic)
- ✅ Much fewer constraints

**Cons:**
- ❌ No groth16 support for BLS12-381 yet in gnark
- ❌ Would need BW6-761 for pairing-based SNARKs (recursive proof)
- ❌ Larger proof size

---

## Option 2: BN254 as SNARK Curve + Emulated BLS12-381 (Current)

```go
// Compile with BN254 scalar field
ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
```

**Inside circuit:**
```go
import "github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"

// BLS12-381 operations are EMULATED
// Each BLS12-381 field element = multiple BN254 elements
```

**Pros:**
- ✅ Groth16 works perfectly (mature, battle-tested)
- ✅ Smaller proof size
- ✅ Ethereum-friendly (BN254 precompiles)

**Cons:**
- ❌ Slower (emulated arithmetic)
- ❌ More constraints (~100x overhead)

---

## Performance Comparison

| Operation | BLS12-381 Native | BN254 + Emulated BLS12-381 |
|-----------|------------------|----------------------------|
| Field addition | ~1 constraint | ~10 constraints |
| Field multiplication | ~1 constraint | ~150 constraints |
| G1 addition | ~10 constraints | ~1,000 constraints |
| Pairing | ~10,000 constraints | ~1,000,000 constraints |

---

## Why We Use Emulated (Option 2)

1. **Groth16 Maturity**: BN254 Groth16 is production-ready
2. **Ecosystem**: Ethereum uses BN254 precompiles
3. **Proof Size**: Smaller proofs for verification
4. **Trade-off**: Accept slower proving time for better verification

---

## Future: Native BLS12-381

When gnark adds native BLS12-381 circuit support:
- Would use BW6-761 as outer curve for recursion
- Much faster proving
- But larger proofs and different proof system

# Circuit Performance: Byte Array vs Single Variable

## Option 1: Byte Array (현재 방식)
```go
DomainType [4]frontend.Variable  // 4 constraints (각 바이트당 범위 체크)
```

**회로에서 사용:**
```go
for i := 0; i < 4; i++ {
    domain[i] = c.DomainType[i]  // 직접 사용, 추가 연산 없음
}
```

**Constraints:**
- 입력 범위 체크: 4 (각 바이트 < 256)
- 복사/사용: 0 (직접 사용)
- **Total: ~4 constraints**

---

## Option 2: Single Variable
```go
DomainType frontend.Variable  // 예: 0x07000000
```

**회로에서 사용:**
```go
// 바이트 분해 필요
bits := api.ToBinary(c.DomainType, 32)  // 32 bits = 4 bytes

for byteIdx := 0; byteIdx < 4; byteIdx++ {
    var byteValue frontend.Variable = 0
    for bitIdx := 0; bitIdx < 8; bitIdx++ {
        bit := bits[byteIdx*8+bitIdx]
        power := 1 << bitIdx
        byteValue = api.Add(byteValue, api.Mul(bit, power))  // 각 비트를 바이트로 재구성
    }
    domain[byteIdx] = byteValue
}
```

**Constraints:**
- ToBinary: ~32 constraints (각 비트 boolean 체크)
- 바이트 재구성: ~32 multiplications + 28 additions
- **Total: ~100+ constraints**

---

## 결론

### 바이트 배열 방식이 유리한 경우:
✅ **바이트 단위 연산이 필요할 때** (SHA256, SSZ 등)
✅ **적은 constraint 수**
✅ **코드 가독성**

### 단일 변수 방식이 유리한 경우:
✅ 산술 연산이 주로 필요할 때 (더하기, 곱하기 등)
✅ 전체 값을 하나의 숫자로 취급할 때

---

## 실제 예시

### DomainType = [7, 0, 0, 0]

**바이트 배열:**
```go
DomainType: [4]frontend.Variable{7, 0, 0, 0}
// Witness: 각 바이트 직접 할당
```

**단일 변수:**
```go
DomainType: frontend.Variable  // 0x07000000 = 117440512
// 회로 안에서 바이트 분해 필요 → 비용 증가
```

---

## 성능 측정 (예상)

| 항목 | 바이트 배열 | 단일 변수 |
|------|------------|----------|
| 입력 constraints | 4 | 1 |
| 바이트 추출 constraints | 0 | ~100 |
| **Total** | **~4** | **~101** |
| Witness 생성 시간 | 빠름 | 빠름 |
| Proving 시간 | 더 빠름 | 느림 |

---

## 권장사항

**현재 방식 (바이트 배열)이 올바릅니다!**

이유:
1. SHA256/SSZ는 바이트 지향 연산
2. Constraint 수 최소화 (25배 이상 절약)
3. 코드 명확성
