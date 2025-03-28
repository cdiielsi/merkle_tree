use merkle_tree::{MerkleTree, hash};

mod merkle_tree;

fn main() {
    // Given a 4 leves tree:
    //
    //       root
    //     /      \
    //   h12        h34
    //   / \        / \
    // h1   h2    h3   h4
    // |    |     |     |
    // data1 data2 data3 data4
    // The array representation would be: [root,h12,h34,h1,h2,h3,h4]
    // With the indexes                     0   1   2   3  4  5   6
    let vector = vec!["1", "2", "3", "4"];
    let mut merkle_tree = MerkleTree::new(vector);

    //Building a manual proof for the assertion
    let hash1 = hash("1"); //idx 3
    let hash3 = hash("3"); //idx 5
    let hash4 = hash("4"); //idx 6

    let hash34 = hash(hash3 + &hash4);
    let mut proof: Vec<u64> = vec![hash1, hash34];

    //Verifying
    assert!(merkle_tree.verify(proof.clone(), 4).unwrap());
    //Generating proof
    assert_eq!(merkle_tree.generate_proof(4).unwrap(), proof.clone());
    //Adding a node
    merkle_tree.add_node("5");
    // Now the tree takes this form:
    //                      root
    //                   /       \
    //                  /         \
    //                 /           \
    //                /             \
    //          h1234                  h5555
    //        /      \               /      \
    //     h12        h34         h55        h55
    //     / \        / \         / \        / \
    //   h1   h2    h3   h4     h5   h5    h5   h5
    //   |    |     |     |     |    |     |     |
    //data1 data2 data3 data4 data5 data6 data6 data6
    //The array representation would be: [root,h1234,h5666,h12,h34,h56,h66,h1,h2,h3,h4,h5,h5,h5,h5]
    //With the indexes                     0     1     2    3   4   5   6  7  8  9  10 11 12 13 14

    //We update de proof
    let hash5 = hash("5"); //idx 11..14
    let hash55 = hash(hash5.clone() + &hash5);
    let hash5555 = hash(hash55.clone() + &hash55);
    proof.push(hash5555);
    assert!(merkle_tree.verify(proof, 8).unwrap());
}
