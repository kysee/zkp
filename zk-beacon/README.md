## Verifier

### Prerequisites

To compile and setup the `ScUpdateVerifierCircuit`,

```bash
go run setup.go
```

To generate `data/proof-data.json`,

```bash
cd circuit
go test -run TestScUpdateVerifierCircuit$ -timeout 20m
cd ..
```

### On-chain verification 
To compile the contract and test,

```bash
cd verifier-contract
npx hardhat compile
ts-node test/deploy.ts
```
