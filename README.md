# Merkle Tree
This is an implementation of a binary merkle tree in rust.

### What is a Merkle Tree?
A merkle tree (also known as a hash tree) is a tree used to store several data in a particular way: every leaf node is labelled with a hash of a data block, and every other node is labelled with a hash of the labels of its children. The tree disposition of the hashes allows for efficient and secure verification of its contents.

### What are a Merkle Trees used for?
Plainly said, a Merkle Tree is for comparing and verifying if two users have the same data. This structure is used for data verification in peer to peer networks, such as bitcoin, so you can efficiently prove that transactions were validated. It's also used for maintaining the integrity of files stored across networks and transmitting files over unreliable channels.

## Quick Start

- To build and run the project, run:
```
make
```
- To run the tests, run:
```
make test
```

## Dependencies
- rust 1.85.0
- sha256 = "1.6.0"

## About this project
The tree structure implemented in this project revolves around an array that should be interpreted as the following example:
Given a 4 leves tree:

              root
            /      \
         h12        h34
         / \        / \
       h1   h2    h3   h4
       |    |     |     |
    data1 data2 data3 data4

We'll have the following array with it's corresponding indexes:
 root | h12 | h34 | h1 | h2 | h3 | h4 
 :---: | :---: | :---: | :---: | :---: | :---: | :---: 
 0 | 1 | 2 | 3 | 4 | 5 | 6 

For hashing I use the Secure Hash Algorithm **SHA-256**.

This implementation supports:

- Building a Merkle Tree out of an array of data of any size:
    This implies having all the hashes computed and inserted into an array as shown previously. In cases where the amount of original data is not a power of 2, the last element of the array is duplicated until the size of the array reaches such size. Then the tree is designed as follows:

 Given a 6 leves tree:   
 
                          root
                       /       \
                      /         \
                     /           \
                    /             \
              h1234                  h5666
            /      \               /      \
         h12        h34         h56        h66
         / \        / \         / \        / \
       h1   h2    h3   h4     h5   h6    h6   h6
       |    |     |     |     |    |     |     |
    data1 data2 data3 data4 data5 data6 data6 data6 

We'll have the following array with it's corresponding indexes:
root | h1234 | h5666 | h12 | h34 | h56 | h66 | h1 | h2 | h3 | h4 | h5 | h6 | h6 | h6 
 :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: 
 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14

- Adding new data to an existing Merkle Tree:
    This implies extending the tree as explained previously or replacing the last repeated elements with the new one along with computing the corresponding hashes.

- Verifying that a given hash is in the Merkle Tree:
    To do this a proof is needed. This proof comes as an array of the minimum amount of hashes needed to compute the root from the hash in question. Eg: for the previous example the proof for the hash in index 11 would be [h6,h66,h123]. Go to https://www.youtube.com/watch?v=n6nEPaE7KZ8 or the other references below for further understanding.

- Giving proof that the Merkle Tree contains an element.
    This means building such an array as the proof described for the previous functionality.

## References
https://brilliant.org/wiki/merkle-tree/ <br />
https://en.wikipedia.org/wiki/Merkle_tree <br />
https://www.youtube.com/watch?v=n6nEPaE7KZ8 <br />
https://decentralizedthoughts.github.io/2020-12-22-what-is-a-merkle-tree/ <br />
https://en.wikipedia.org/wiki/SHA-2
