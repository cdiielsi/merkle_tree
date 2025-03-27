# merkle_tree
This is an implementation of a binary merkle tree in rust.

A merkle tree (also known as a hash tree) is a tree in which every leaf node is labelled with a hash of a data block, and every other node is labelled with a hash of the labels of its children. The merkle tree implemented in this case only works for String data.

This structure is used for data verification in peer to peer networks, such as bitcoin or git.

This implementation will support:
- Building the Merkle Tree out of an array.
- Adding nodes to an existing Merkle Tree.
- Verifying that a given hash is in the Merkle Tree.
- Giving proof that the Merkle Tree contains an element.

# References
https://brilliant.org/wiki/merkle-tree/ <br />
https://en.wikipedia.org/wiki/Merkle_tree