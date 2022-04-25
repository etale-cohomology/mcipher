# mcipher

This is a straightforward generalization of Salsa20 from 256-bit keys and 512-bit blocks to 16384-bit keys and 32768-bit blocks.
See [this Salsa20 implementation](https://github.com/etale-cohomology/salsa20) for some details on how Salsa20 works.

# building

    gcc-8 mcipher.c -o mcipher  &&  ./mcipher
