# Prototype Implementation of the WeakFlood2Flood Protocol
We here provide a simple prototype implementation in C++ of the protocol `WeakFlood2Flood` from the paper [Asymptotically Optimal Message Dissemination with Applications to Blockchains](https://eprint.iacr.org/2022/1723). The purpose of this prototype is to bound the computational overhead of the protocol. It has not been optimized and tested thoroughly and should not be used in production.

The prototype uses Reed-Solomon codes from the [Schifra library](https://github.com/ArashPartow/schifra)
and implements a simple accumulator based on SHA256 Merkle trees using the [merklecpp library](https://github.com/microsoft/merklecpp/).

## Prerequisites
To compile the code on Linux, one needs to install:

- GCC with C++17 Support
- libssl-dev
- libtbb-dev

## Configuration
The file `wf2f.cpp` defines three constants at the top that can be modified to test the performance of the protocol in different scenarios:

- `NUM_SHARES` defines into how many shares the sender splits the message. This corresponds to the parameter µ in the paper and is initially set to `10`.
- `MAX_DELETIONS` defines the parameter of the error correcting code determining how many of the shares can get lost without preventing reconstruction. It corresponds to the parameter ϱ in the paper and is initially set to `2`.
- `MSG_LENGTH` defines the number of bytes the sender wants to disseminate. It is initially set to `1024 * 1024`, i.e., a 1 megabyte message is assumed.

## Compiling
To compile the code, execute
```
g++ -std=c++17 -O3 wf2f.cpp -lcrypto -ltbb
``` 

## Usage
The compiled code can be executed in the command line and does not take any arguments.

The program first generates a message consisting of `MSG_LENGTH` random bytes and executes the sender protocol of `WeakFlood2Flood` to obtain a vector of `NUM_SHARES` packets that are to be disseminated using a `WeakFlood` protocol.
Next, `MAX_DELETIONS` random packets are chosen and their accumulated values are set to the hash of the empty string, to simulate corrupted packets.
Finally, the receiver protocol of `WeakFlood2Flood` is executed on the obtained packets. The obtained message is then compared to the original one to determine whether it would have been received successfully.

The program outputs the times to execute the sender and receiver protocols, respectively, and whether the correct message was decoded. Note that the `WeakFlood` subprotocol is not implemented, i.e., no messages are actually send over a network. This program thus only measures the computational overhead of `WeakFlood2Flood` over an assumed `WeakFlood` protocol.
