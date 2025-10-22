# ZK Asset - Solidity Implementation

Private asset transfer system using zero-knowledge proofs, ported from gnark to Solidity.

## Features

- **Confidential Transfers**: Hidden sender, receiver, and amount
- **Double-Spend Prevention**: Nullifier-based UTXO system
- **Recipient-Only Visibility**: Encrypted notes using ECDHE
- **Merkle Tree**: Efficient note commitment tracking
- **PLONK Proofs**: BN254 curve with MiMC hash

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Go Circuit    │───▶│  Solidity        │───▶│  Smart Contract │
│   (gnark)       │    │  Verifier        │    │  (ZKAsset)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                        │                        │
        ▼                        ▼                        ▼
  Proof Generation         Proof Verification      State Management
```

## Quick Start

### 1. Generate Verifier

```bash
# Generate Solidity verifier from gnark circuit
go run generate_verifier.go
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Compile Contracts

```bash
npx hardhat compile
```

### 4. Run Tests

```bash
npx hardhat test
```

### 5. Deploy

```bash
# Start local network
npx hardhat node

# Deploy contracts
npx hardhat run scripts/deploy.js --network localhost
```

## Contract Interface

### ZKAsset.sol

Main contract for private asset transfers.

#### Key Functions

- `transfer(proof, publicInputs, encryptedNote)` - Execute private transfer
- `deposit(commitment)` - Add note commitment to tree
- `getMerkleProof(leafIndex)` - Generate merkle inclusion proof
- `isNullifierUsed(nullifier)` - Check nullifier status

#### Public Inputs

Transfer proofs require these public inputs:
1. `merkleRoot` - Current merkle tree root
2. `nullifier` - Prevents double-spending
3. `newNoteCommitment` - Recipient's new note
4. `changeNoteCommitment` - Sender's change note (or 0)

### PlonkVerifier.sol

Auto-generated PLONK verifier from gnark circuit.

## Workflow

### 1. Deposit (Initial Setup)

```solidity
// Create note commitment
uint256 commitment = hash(version, pubKey, balance, salt);

// Deposit to contract
zkAsset.deposit(commitment);
```

### 2. Transfer

```javascript
// Off-chain: Generate proof using Go helper
const proof = await generateTransferProof({
  fromPrivateKey: senderSk,
  fromNote: spendingNote,
  merkleProof: proof,
  toPublicKey: receiverPk,
  amount: transferAmount,
  fee: txFee
});

// On-chain: Submit transfer
await zkAsset.transfer(
  proof.proof,
  proof.publicInputs,
  encryptedNote
);
```

### 3. Receive

```javascript
// Recipient decrypts their note
const sharedNote = decryptSharedNote(
  encryptedNote,
  receiverPrivateKey
);

// Reconstruct full note
const note = sharedNote.toNoteOf(receiverPublicKey);
```

## Security Considerations

- **Trusted Setup**: Uses unsafe KZG SRS for demo (replace in production)
- **Hash Function**: Simplified hash used (implement proper MiMC)
- **Key Management**: Secure private key handling required
- **Merkle Tree**: Fixed depth limits scalability

## Testing

The test suite covers:
- Contract deployment
- Note commitment deposits
- Merkle tree operations
- Nullifier tracking
- Access control
- Edge cases and capacity limits

```bash
# Run specific test
npx hardhat test --grep "Should allow deposits"

# Run with gas reporting
REPORT_GAS=true npx hardhat test
```

## File Structure

```
├── contracts/
│   ├── PlonkVerifier.sol    # Auto-generated verifier
│   └── ZKAsset.sol          # Main asset contract
├── scripts/
│   └── deploy.js            # Deployment script
├── test/
│   └── ZKAsset.test.js      # Test suite
├── generate_verifier.go     # Verifier generation
├── proof_helper.go          # Proof generation helper
└── README.md               # This file
```

## Production Checklist

- [ ] Replace unsafe SRS with production setup
- [ ] Implement proper MiMC hash function
- [ ] Add access controls and governance
- [ ] Optimize gas usage
- [ ] Add slashing conditions
- [ ] Implement fee mechanism
- [ ] Add emergency pause functionality

## Integration with Go Backend

The Solidity contracts work alongside the existing Go implementation:

- **Go**: Circuit definition, proof generation, key management
- **Solidity**: On-chain verification, state management, transfers
- **Bridge**: JSON-RPC for proof submission, event monitoring

This allows leveraging gnark's excellent proving performance while providing Ethereum compatibility.