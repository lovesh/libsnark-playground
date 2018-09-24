# Libsnark playground

Playing with Zk-SNARKs. Some of the code taken from libsnark tutorial repositories from [Christian Lundkvist](https://github.com/christianlundkvist/libsnark-tutorial) and [Howard Wu](https://github.com/howardwu/libsnark-tutorial). The latter contains the build instructions.
1. [Example to prove knowledge of factors of a number](src/factorisation.cpp), i.e given a public output `c`, prove the knowledge of 2 numbers `a` and `b` such that `a * b = c`.
2. [Prove the knowledge of pre-image of a sha256 hash](src/sha256.cpp). Uses libsnark's sha256 gadget. Byte representation of inputs and output can be generated using [python helper script](src/generate_sha256_gadget_tests.py). Use the function `short_string_hash` to generate bytes.
3. [MiMC-Fiestel hash pre-image](src/longsightf-gadget.hpp). 2 implementations, [one](https://github.com/josojo/mimcHashTimings) from [josojo](https://github.com/josojo) that does exponentiation (x^3) during round and other does inverse (x^-1) during the round as suggested by [Dmitry K.](https://github.com/khovratovich) 
