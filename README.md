# Project List

## Project 1: SM4 Software Implementation and Optimization
**a)** Optimize SM4 software execution efficiency starting from basic implementation. Optimization should cover:
- T-table
- AESNI
- Latest instruction sets (GFNI, VPROLD, etc.)

**b)** Implement optimized software for SM4-GCM mode based on SM4 implementation.

## Project 2: Digital Watermark-based Image Leak Detection
- Implement image watermark embedding and extraction (can be based on open-source projects)
- Conduct robustness testing including but not limited to:
  - Flipping
  - Translation
  - Cropping
  - Contrast adjustment

## Project 3: Circom Implementation of Poseidon2 Hash Algorithm Circuit
1. Implement Poseidon2 hash algorithm with parameters (n,t,d)=(256,3,5) or (256,2,5) (refer to Table1 in reference doc1)
2. Circuit specifications:
   - Public input: Poseidon2 hash value
   - Private input: Hash preimage
   - Consider only one block for hash algorithm input
3. Generate proof using Groth16 algorithm

**References:**
1. [Poseidon2 Hash Algorithm](https://eprint.iacr.org/2023/323.pdf)
2. [Circom Documentation](https://docs.circom.io/)
3. [Circom Circuit Examples](https://github.com/iden3/circomlib)

## Project 4: SM3 Software Implementation and Optimization
**a)** Similar to Project 1, start from basic SM3 software implementation and optimize execution efficiency (refer to Prof. Fu Yong's PPT)  
**b)** Verify length-extension attack based on SM3 implementation  
**c)** Build Merkle tree (100k leaf nodes) according to RFC6962 and construct:
- Leaf existence proof
- Leaf non-existence proof

## Project 5: SM2 Software Implementation Optimization
**a)** Implement basic SM2 and algorithm improvements (Python recommended due to complexity of C implementation)  
**b)** Create PoC verification for signature algorithm misuse mentioned in "20250713-wen-sm2-public.pdf", including:
- Derivation documentation
- Verification code  
**c)** Forge Satoshi Nakamoto's digital signature

## Project 6: Google Password Checkup Verification
Based on Prof. Liu Weiran's report and [reference paper](https://eprint.iacr.org/2019/723.pdf) (Section 3.1/Figure 2 protocol), implement the protocol (programming language unrestricted).
