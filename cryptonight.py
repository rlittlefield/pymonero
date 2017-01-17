from Keccak import Keccak as keccak_class
import binascii
from jhhash import jhhash
import groestl_hash
import pyblake2
import skein

# this pure-python aes is slow as dirt even after some modifications
# we should do some cffi magic to use aes-ni directly if possible
import aes as aes_lib
aes = aes_lib.AES()


def eight_byte_mul(a, b):
    a_first_eight = a[:8]
    b_first_eight = b[:8]
    a_int = int.from_bytes(bytes(bytearray(a_first_eight)), 'little')
    b_int = int.from_bytes(bytes(bytearray(b_first_eight)), 'little')
    mul = a_int * b_int
    result = mul.to_bytes(16, 'little')
    swapped = result[8:16] + result[:8]
    return swapped


def eight_byte_add(a, b):
    a_pair = int.from_bytes(a[:8], 'little') + int.from_bytes(a[8:], 'little')
    b_pair = int.from_bytes(b[:8], 'little') + int.from_bytes(b[8:], 'little')
    a = (a_pair % 0x10000000000000000).to_bytes(8, 'little')
    b = (b_pair % 0x10000000000000000).to_bytes(8, 'little')
    result = bytearray(a + b)
    return result


def scratchpad_address(sixteen_bytes):
    '''
    From Spec:
        "When a 16-byte
        value needs to be converted into an address in the scratchpad, it is
        interpreted as a little-endian integer, and the 21 low-order bits are
        used as a byte index. However, the 4 low-order bits of the index are
        cleared to ensure the 16-byte alignment."
    '''
    mask = 0b111111111111111111111
    bigint = int.from_bytes(bytes(sixteen_bytes), 'little')
    address = ((bigint & mask) >> 4) << 4
    return address


def make_round_keys(aes_key_bytearray):
    aes_key = bytes(aes_key_bytearray)

    '''
    From Spec: "The bytes 0..31 of the Keccak final state are
    interpreted as an AES-256 key [AES] and expanded to 10 round keys."
    '''

    # expand keys. See aes_expand_key at https://github.com/monero-project/monero/blob/master/src/crypto/slow-hash.c
    expanded_key = aes.expandKey(aes_key, 32, 320) # 320 bytes is 1600 bits

    # split the expanded key into 10 lists of 32 integers. Each integer is 1 byte
    roundkey_chunked_bytes = [expanded_key[i:i+32] for i in range(0, len(expanded_key), 32)]
    round_keys = []
    for i in roundkey_chunked_bytes:
        # smush the chunk together again into a 32 bytes object
        rk_bytes = bytes(bytearray(i))
        # attach the new round key to reference later when filling the scratchpad
        round_keys.append(rk_bytes)
    return round_keys

def run(start):
    # See spec at: https://cryptonote.org/cns/cns008.txt
    # AES code from: http://anh.cs.luc.edu/331/code/aes.py (Apache License, Version 2.0)
    # JH hash from https://bitbucket.org/lshift/jh-slow-python

    keccak = keccak_class()
    hex_message = binascii.hexlify(start).decode()
    keccak_result = keccak.Keccak((len(hex_message)//2, hex_message))
    state = keccak_result[1]

    # aes_key = sha3.keccak_256(start).digest() # nope. Apparently cryptonight likes the internal state
    # use the internal 200 bytes of the keccak function
    # the first 32 bytes become an AES key (0:31)

    state_bytes = bytearray()
    count = 0
    for i in range(5):
        for y in range(5):
            state_bytes[count:] = state[i][y].to_bytes(8, 'little')
            count += 8

    round_keys = make_round_keys(state_bytes[0:32])

    '''
    From Spec: "The bytes 64..191
    are extracted from the Keccak final state and split into 8 blocks of
    16 bytes each."

    Last one appears to not be used:
        state[4][4]=192-199
    '''

    block_bytes = state_bytes[64:192]
    # pair every 16 bytes
    last_blocks = [block_bytes[i:i+16] for i in range(0, len(block_bytes), 16)]

    '''
    From Spec:
        "Each block is encrypted using the following procedure:

              for i = 0..9 do:
                  block = aes_round(block, round_keys[i])"
    '''
    scratchpad = bytearray()

    while len(scratchpad) < 2097152:
        base = len(scratchpad)
        new_blocks = []
        for i, two_bytes in enumerate(last_blocks):
            # From Spec:
            #     The bytes 64..191 are extracted from the Keccak final state and split into 8 blocks of 16 bytes each.
            #     Note that
            #     unlike in the AES encryption algorithm, the first and the last rounds
            #     are not special.
            # Start by converting the block_bytes bytes object into a bytearray, then list for compatibility
            block = list(bytearray(two_bytes))
            # This was taking a very long time using the pure-python aes implementation
            # so I dropped in a lookup table for the galois multiplication from
            # https://raw.githubusercontent.com/caller9/pythonaes/master/aespython/aes_tables.py
            # It was MIT licensed.
            encrypted_block = aes.aes_round(block, round_keys[i])
            scratchpad[base+(i*16):base+(i*16+16)] = encrypted_block
            new_blocks.append(encrypted_block)
        last_blocks = new_blocks



    '''
    From Spec:
        "Prior to the main loop, bytes 0..31 and 32..63 of the Keccak state
        are XORed, and the resulting 32 bytes are used to initialize
        variables a and b, 16 bytes each."

    '''
    xord = [i ^ y for i, y in zip(state_bytes[0:32], state_bytes[32:64])]
    a = bytearray(xord[0:16])
    b = bytearray(xord[16:32])

    # main loop.
    for index in range(524288):
        address = scratchpad_address(a)
        aes_result = aes.aes_round(scratchpad[address:address+16], a)
        b_xord = [i ^ y for i, y in zip(b, aes_result)]
        scratchpad[address:address+16] = b_xord
        b = aes_result
        address = scratchpad_address(b)
        mul = eight_byte_mul(b, scratchpad[address:address+16])
        a = eight_byte_add(a, mul)
        a_xord = [i ^ y for i, y in zip(a, scratchpad[address:address+16])]
        scratchpad[address:address+16] = a
        a = a_xord

    '''
    From Spec:
        "After the memory-hard part, bytes 32..63 from the Keccak state are
        expanded into 10 AES round keys in the same manner as in the first
        part."
    '''

    round_keys = make_round_keys(state_bytes[32:64])


    '''
    From Spec:
        "Bytes 64..191 are extracted from the Keccak state and XORed with the
        first 128 bytes of the scratchpad. Then the result is encrypted in
        the same manner as in the first part, but using the new keys. The
        result is XORed with the second 128 bytes from the scratchpad,
        encrypted again, and so on."
    '''
    # block_bytes already has the correct bytes loaded from the state

    last_bytes = block_bytes
    round_key_index = 0
    for position in range(0, 2097152, 128):
        sp_128 = scratchpad[position:position+128]
        xord = [i ^ y for i, y in zip(last_bytes, sp_128)]
        last_bytes = aes.aes_round(xord, round_keys[round_key_index])
        round_key_index += 1
        if round_key_index > 9:
            round_key_index = 0

    '''
    From Spec:
        "the result is
        encrypted the last time, and then the bytes 64..191 in the Keccak
        state are replaced with the result."
    '''
    state_bytes[64:192] = last_bytes

    '''
    From Spec:
        "Then, the Keccak state is passed
        through Keccak-f (the Keccak permutation) with b = 1600.

        Then, the 2 low-order bits of the first byte of the state are used to
        select a hash function: 0=BLAKE-256 [BLAKE], 1=Groestl-256 [GROESTL],
        2=JH-256 [JH], and 3=Skein-256 [SKEIN]. The chosen hash function is
        then applied to the Keccak state, and the resulting hash is the
        output of CryptoNight."
    '''
    hex_message = binascii.hexlify(state_bytes).decode()
    keccak_result = keccak.Keccak((len(hex_message)//2, hex_message))
    state = keccak_result[1]
    state_bytes = bytearray()
    count = 0
    for i in range(5):
        for y in range(5):
            state_bytes[count:] = state[i][y].to_bytes(8, 'little')
            count += 8

    first_byte = state_bytes[0]

    if (first_byte & 3) == 3:
        # skein
        print('skein!')
        hex_digest = skein.skein256(bytes(state_bytes)).hexdigest()
        pass
    elif (first_byte & 2) == 2:
        # JH
        print('jh!')
        raw_hash = jhhash.hashbytes(256, bytes(state_bytes))
        hex_digest = binascii.hexlify(raw_hash)
        pass
    elif (first_byte & 1) == 1:
        # Groestl
        print('Groestl!')
        raw_hash = groestl_hash.getPoWHash(bytes(state_bytes))
        hex_digest = binascii.hexlify(raw_hash)
        pass
    else:
        # blake
        print('blake!')
        hex_digest = pyblake2.blake2s(bytes(state_bytes), digest_size=32).hexdigest()
        pass

    return hex_digest


start = b'This is a test'
digest = run(start)
print(digest)




