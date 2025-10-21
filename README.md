## ZKP Samples

### `zk-vote`

This is a voting system using ZKP.  

- Secret Ballot  
  Voters can vote without revealing who they are.  
  
- Equal Ballot (One Man One Vote)  
  One Man can not choose more than one.  
  
- Changeable Voting    
  Voters can change their choices at any time during the election.  

### `zk-asset`

This is a simple asset transfer system using ZKP. 

- Confidentiality  
  The sender address, receiver address, and transfer amount cannot be inferred.

- Recipient-Only Visibility  
  Only the recipient can confirm the amount they have received.  
  This is implemented by generating and transmitting an encrypted Secret Note using ECDHE (Elliptic Curve Diffie-Hellman Ephemeral).

- Double-Spend Prevention  
  This is enforced through the application of a Nullifier.

- Core Technologies  
  PLONK based on BN254, MiMC and ChaCha20-Poly1305
  
### `zk-age`

Not yet.

---

*All samples use [`gnark` zk-SNARK library](https://github.com/ConsenSys/gnark).*