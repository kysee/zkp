# Sync Committee Verification

Ethereum beacon chain sync committee signature verification implementation.

## File Structure

- `verify.go`: sync_aggregate verification code
- `lcupdate.json`: Light client update data (slot 9052234)
- `sync-committee-1104.json`: Sync committee period 1105 public keys

## Key Features

### 1. JSON Data Loading
- Load light client update and sync committee public keys from JSON files

### 2. Sync Committee Bits Parsing
- Parse `sync_committee_bits` to identify which validators participated in signing
- 512 sync committee members represented as a bitmask

### 3. Public Key Aggregation
- Aggregate BLS public keys of participating validators
- Uses Herumi BLS library

### 4. Signing Root Computation
- SSZ hashing of beacon block header
- Uses DOMAIN_SYNC_COMMITTEE (0x07000000)
- Computes domain using fork version and genesis validators root
- Uses Protolambda zrnt library's SSZ implementation

### 5. BLS Signature Verification
- Verifies BLS signature using aggregated public key and signing root

## How to Run

```bash
go run zk-beacon/verify.go
```

## Output Example

```
Loaded sync committee for period 1105 with 512 pubkeys
Loaded light client update for slot 9052234
Aggregated 474 public keys
Verification SUCCEEDED!
```

## Dependencies

- `github.com/herumi/bls-eth-go-binary/bls`: BLS12-381 signature library
- `github.com/protolambda/zrnt/eth2/beacon/common`: Ethereum 2.0 types and SSZ implementation
- `github.com/protolambda/ztyp/tree`: SSZ hashing functions

## Network Parameters

Current configuration:

- Genesis Validators Root: `0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078`
- Fork Version: `0x90000075` (Fulu fork)
- Slot: 9052234 (Period 1105)

To use different networks, modify parameters in `computeSigningRoot` function (verify.go:181-185).

## Notes

1. **Network-specific Settings**: Genesis validators root and fork version differ by network. For mainnet or other testnets, you must change to the appropriate network values.

2. **Sync Committee Period**: Ensure the sync committee JSON file matches the correct period. Use the sync committee corresponding to the light client update's slot period.

## Code Structure

```go
type LightClientUpdate struct {
    Data struct {
        AttestedHeader    LightClientHeader  // Block header to verify
        NextSyncCommittee NextSyncCommittee  // Next sync committee
        SyncAggregate     SyncAggregate      // Signature data
        SignatureSlot     string             // Signature slot
    }
}

type SyncAggregate struct {
    SyncCommitteeBits      string  // Participating validator bitmask
    SyncCommitteeSignature string  // BLS aggregated signature
}
```

## Troubleshooting

### Signature Verification Failure

1. **Genesis Validators Root**: Verify using correct network's genesis validators root
2. **Fork Version**: Ensure using the fork version active at the slot
3. **Sync Committee Period**: Confirm using correct period's sync committee
4. **BLS Library Settings**: Verify `bls.SetETHmode(bls.EthModeDraft07)` is set correctly

### Public Key Aggregation Issues

When using Herumi BLS library:
- Initialize `aggPubkey` with first pubkey
- Accumulate subsequent pubkeys using `Add` method
- All pubkeys must be G1 points on the BLS12-381 curve