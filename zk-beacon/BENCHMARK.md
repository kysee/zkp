## 12.05 (2)

Add to verify that the state_root includes the next_sync_committee.

### Constraints

| Circuit | Constraints |
| --- | --- |
| BLSVerifierCircuit | 2717079 |
| SyncCommitteeVerifierCircuit | 1249667 |

### Benchmark

goos: darwin  
goarch: arm64  
pkg: github.com/kysee/zkp/zk-beacon  
cpu: Apple M1 Max  
BenchmarkBLSVerifierCircuit

| Operation | Time                |
| --- |---------------------|
| ProofGeneration | 10406593625 ns/op |
| ProofVerification | 1796808 ns/op     |

## 12.05 (1)

Add aggregation of BLS pubkeys of curr_sync_committee to BLSVerifierCircuit.

### Constraints

| Circuit | Constraints |
| --- | --- |
| BLSVerifierCircuit | 2401385 |
| SyncCommitteeVerifierCircuit | 1249667 |

### Benchmark

goos: darwin  
goarch: arm64  
pkg: github.com/kysee/zkp/zk-beacon  
cpu: Apple M1 Max  
BenchmarkBLSVerifierCircuit  

| Operation | Time                |
| --- |---------------------|
| ProofGeneration | 9484611792 ns/op |
| ProofVerification | 1745043 ns/op     |

## 12.04 (2)

To computing domain is executed out of the Circuit.

### Constraints

| Circuit | Constraints |
| --- | --- |
| BLSVerifierCircuit | 2175941 |
| SyncCommitteeVerifierCircuit | 1249667 |

### Benchmark

goos: darwin  
goarch: amd64  
pkg: github.com/kysee/zkp/zk-beacon  
cpu: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz  
BenchmarkBLSVerifierCircuit

| Operation | Time                |
| --- |---------------------|
| ProofGeneration | 8138772207 ns/op |
| ProofVerification | 1098043 ns/op     |

## 12.05 (1)

All verifications are executed in the Circuit.

### Constraints
 
| Circuit | Constraints |
| --- | --- |
| BLSVerifierCircuit | 2227930 |
| SyncCommitteeVerifierCircuit | 1249667 |

### Benchmark

goos: darwin  
goarch: amd64  
pkg: github.com/kysee/zkp/zk-beacon  
cpu: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz  
BenchmarkBLSVerifierCircuit

| Operation | Time                |
| --- |---------------------|
| ProofGeneration | 8418840309 ns/op |
| ProofVerification | 1094455 ns/op     |
