## Implementation from scratch

## Goals

- Implement from programming bitcoin.
- Build the SHA 256 using the NIST.FIPS.180
- Write about it in the blog post.

Note:- While running the karpathy code avoid using the .crypto in .crypto.sha256. 
- Get-HashFile in powershell might work.
- Check if CertUtil -hashfile is working or not. (Error:- Expected 2 args received 3)


### TO DO

-:done:  Constants of sha256
-:done: Preprocessing and padding
-:done: parsing the message.
- : tests done : Get it up and running on Linux, and write the tests for sha256.
- :done: Repeat for sha512. Match the hex digests.

### Finite fields

Elliptic key cryptography
Understand ECC  the math behind ECC
ECC gives us the signing and verification algorithms.

### Serialization

#### Uncompressed SEC format

- Public key in the Elliptic curve is a coordinate in the form of (x, y) We need to serialize this data.

Here is how the uncompressed SEC format for a given point P = (x,y) is generated:

1. Start with the prefix byte, which is 0x04.

2. Next, append the x coordinate in 32 bytes as a big-endian integer.

3. Next, append the y coordinate in 32 bytes as a big-endian integer.

#### Compressed SEC format



### Keys and addresses

A bitcoin wallet contains a collection of both public keys and private keys. The private key is usually picked at random.  From the private key we use an elliptic  curve multiplication to generate a public key. From the public key  we use a one way cryptographic hash function to generate a bitcoin address. (From chapter 4 of the Bitcoin book).

### Generating a Private key from  a random number.

Find a secure source of entroy or randomness. Find a number between 1 and 2^256. 

Warning: Use a cryptographically secure pseudorandom number generator (CSPRNG) with a seed from a source of sufficient entropy. Study the documentation of the random number generator library.Correct implementation of the CSPRNG is critical to the security of the keys.

