Work in progress for cryptonight Proof of Work in python.

Relies heavily on hashing and AES libraries, and should be compatible with python 3.6

This isn't ready to use yet because it is extremely slow (0.1 hashes per second), and doesn't actually produce valid hashes. Not sure why yet, most likely something to do with the way I read and write some of the intermediate scratchpad state, or interpret the keccak state into a bytearray.

The AES library has been modified to work with python 3 and use the aes_lookup tables from another aes python implementation. The JH hash library is included here, and is has its own license. Changes I've made to it (better python 3 support) are licensed with their license. The keccak library used is the only one that would let me extract the internal state object, as cryptonight likes to only play with internals, and my changes to it are also placed into public domain to the extent allowed.

All other parts of the project are Copyright 2017, J. Ryan Littlefield

I'll have a real license for my work in "cryptonight.py" soon, which is the main file for this project at the moment. 