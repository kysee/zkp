
## 12.04 (2)

To computing domain is executed out of the Circuit.

### Constraints

Compiling BLSVerifierCircuit circuit...  
✓ Circuit has 2175941 constraints  
Generating proving and verifying keys...  
✓ Setup complete  
Loading SyncCommitteeVerifierCircuit circuit...  
✓ Circuit has 1249667 constraints  
Loading proving and verifying keys...  
✓ Setup complete

### Benchmark

goos: darwin  
goarch: amd64  
pkg: github.com/kysee/zkp/zk-beacon  
cpu: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz  
BenchmarkBLSVerifierCircuit  
BenchmarkBLSVerifierCircuit/ProofGeneration  
BenchmarkBLSVerifierCircuit/ProofGeneration-16                 1        8138772207 ns/op  
BenchmarkBLSVerifierCircuit/ProofVerification  
BenchmarkBLSVerifierCircuit/ProofVerification-16            1064           1098043 ns/op  
 

## 12.05 (1)

All verifications are executed in the Circuit.

### Constraints

Loading BLSVerifierCircuit circuit...  
✓ Circuit has 2227930 constraints  
Loading proving and verifying keys...  
✓ Setup complete  
Loading SyncCommitteeVerifierCircuit circuit...  
✓ Circuit has 1249667 constraints  
Loading proving and verifying keys...  
✓ Setup complete  

### Benchmark

goos: darwin  
goarch: amd64  
pkg: github.com/kysee/zkp/zk-beacon  
cpu: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz  
BenchmarkBLSVerifierCircuit  
BenchmarkBLSVerifierCircuit/ProofGeneration  
BenchmarkBLSVerifierCircuit/ProofGeneration-16                 1        8418840309 ns/op  
BenchmarkBLSVerifierCircuit/ProofVerification  
BenchmarkBLSVerifierCircuit/ProofVerification-16            1058           1094455 ns/op  
