use sha256::digest;

/// Implementation of merkle tree. The struct has a field for the tree structure which revolves around an array that
/// should be interpreted as the following example:
/// Given a 4 leves tree:
///
///       root
///     /      \
///   h12        h34
///   / \        / \
/// h1   h2    h3   h4
/// |    |     |     |
/// data1 data2 data3 data4
/// The array representation would be: [root,h12,h34,h1,h2,h3,h4]
/// With the indexes                     0   1   2   3  4  5   6
/// It also has a field for the last index you can find a data hash (in this case 6), and a field that specifies the
/// total leaves of data the tree including the repeated leaves, this is needed for the add_node method.

pub struct MerkleTree {
    tree: Vec<String>,
    last_data_index: usize,
    og_data_vector_size: usize,
    leaves_amount: usize,
}
impl MerkleTree {
    /// Builds the tree concatenating the diferent levels into one array.
    /// The final array tree goes from root to leaves -> [root....branch_n, branch_n+1....leaf].
    pub fn new(data_vector: Vec<&str>) -> Self {
        let pow2_data_vector = extend_to_power2_size(&data_vector);
        let mut level_n = vec![];
        for data in &pow2_data_vector {
            level_n.push(digest(data.clone()));
        }
        let mut current_tree = vec![];
        for level in 0..(pow2_data_vector.len() as f64).sqrt().ceil() as usize {
            //Amount of levels
            let mut level_n_minus1 = vec![];
            for i in (0..level_n.len()).step_by(2) {
                //Build new level from the previous one
                level_n_minus1.push(digest(level_n[i].clone() + &level_n[i + 1]));
            }
            let next_current_level = level_n_minus1.clone();
            if level == 0 {
                level_n_minus1.append(&mut level_n); //Concatenating the leaves.
            } else {
                level_n_minus1.append(&mut current_tree); //Concatenating the previous levels.
            }
            current_tree = level_n_minus1.clone();
            level_n = next_current_level;
        }
        let last_data_index = current_tree.len() - pow2_data_vector.len() + data_vector.len() - 1;

        Self {
            tree: current_tree.clone(),
            last_data_index: last_data_index,
            og_data_vector_size: data_vector.len(),
            leaves_amount: pow2_data_vector.len(),
        }
    }

    /// Given a proof and an index of a data hash the function must determine wether the proof is correct.
    /// For understanding this function we can consider the following tree:
    ///               root
    ///          h12        h34
    ///        h1   h2    h3   h4
    ///        |    |     |     |
    ///     data1 data2 data3 data4
    /// The array representation would be: [root,h12,h34,h1,h2,h3,h4]
    /// With the indexes                     0   1   2   3  4  5   6
    pub fn verify(&self, proofs: Vec<String>, mut leaf_index: usize) -> Option<bool> {
        let mut hash_for_verification = self.tree.get(leaf_index)?.clone();
        for proof in proofs {
            if leaf_index % 2 == 1 {
                // if index is odd we are on a left branch, so the verification must be computed concatenating the proof second
                hash_for_verification = digest(hash_for_verification.to_owned() + &proof);
            } else {
                // if index is even we are on a right branch, so the verification must be computed concatenating the proof first
                hash_for_verification = digest(proof.clone() + &hash_for_verification);
                leaf_index -= 1; //if it's a right child this is necesary to calculate its parent
            }
            leaf_index = leaf_index / 2;
        }
        let ret = hash_for_verification == *self.tree.get(0)?;
        Some(ret)
    }

    /// Given an index of a data hash the function must return the proof that the tree contains that data hash.
    pub fn generate_proof(&self, mut node_index: usize) -> Option<Vec<String>> {
        let mut proof: Vec<String> = vec![];
        if node_index > self.tree.len() {
            return None;
        }
        while node_index > 0 {
            if node_index % 2 == 1 {
                // if index is odd we are on a left branch, so the verification must be computed concatenating the proof second
                proof.push(self.tree.get(node_index + 1)?.clone());
            } else {
                // if index is even we are on a right branch, so the verification must be computed concatenating the proof first
                proof.push(self.tree.get(node_index - 1)?.clone());
                node_index -= 1; //if it's a right child this is necesary to calculate its parent
            }
            node_index = node_index / 2;
        }
        Some(proof)
    }

    /// Returns a merkle tree with a new node, if the total amount of data is not a power of 2
    /// If the true amount of data is a power of two the method "creates" another tree of the same size
    /// only from the new data, like so:
    ///                      root
    ///                   /       \
    ///                  /         \
    ///                 /           \
    ///                /             \
    ///          h1234                  h5555
    ///        /      \               /      \
    ///     h12        h34         h55        h55
    ///     / \        / \         / \        / \
    ///   h1   h2    h3   h4     h5   h5    h5   h5
    ///   |    |     |     |     |    |     |     |
    ///data1 data2 data3 data4 data5 data5 data5 data5
    ///The array representation would be: [root,h1234,h5666,h12,h34,h56,h66,h1,h2,h3,h4,h5,h5,h5,h5]
    ///With the indexes                     0     1     2    3   4   5   6  7  8  9  10 11 12 13 14
    /// If that's not the case we know we have repeated data in the tree, so the hash of the new data is inserted
    /// next to the last data index registered, the other nodes from that point on are changed as well to have
    /// a consistent structure. Here's an example:
    ///                      root
    ///                   /       \
    ///                  /         \
    ///                 /           \
    ///                /             \
    ///          h1234                  h5666
    ///        /      \               /      \
    ///     h12        h34         h56        h66
    ///     / \        / \         / \        / \
    ///   h1   h2    h3   h4     h5   h6    h6   h6
    ///   |    |     |     |     |    |     |     |
    ///data1 data2 data3 data4 data5 data6 data6 data6
    ///The array representation would be: [root,h1234,h5666,h12,h34,h56,h66,h1,h2,h3,h4,h5,h6,h6,h6]
    ///With the indexes                     0     1     2    3   4   5   6  7  8  9  10 11 12 13 14
    pub fn add_node(&mut self, data: &str) -> Option<()> {
        if !is_power_of_2(self.og_data_vector_size) {
            //If tree has repeated data because of padding
            for index in self.last_data_index + 1..self.tree.len() {
                self.tree[index] = digest(data);
                let mut node_index = index as usize;
                while node_index > 1 {
                    if node_index % 2 == 1 {
                        // if index is odd we are on a left branch, so the verification must be computed concatenating the proof second
                        self.tree[node_index / 2] = digest(
                            self.tree.get(node_index)?.to_owned()
                                + self.tree.get(node_index + 1)?,
                        );
                    } else {
                        // if index is even we are on a right branch, so the verification must be computed concatenating the proof first
                        self.tree[(node_index - 1) / 2] = digest(
                            self.tree.get(node_index - 1)?.to_owned()
                                + self.tree.get(node_index)?,
                        );
                        node_index -= 1; //if it's a right child this is necesary to calculate its parent
                    }
                    node_index = node_index / 2;
                }
            }
            self.last_data_index += 1;
        } else {
            let mut new_data = digest(data);
            let mut current_tree = vec![];
            let mut computed_base = vec![];
            let mut level_start_index = self.tree.len() - self.og_data_vector_size;
            let mut level_end_index = self.tree.len();
            let mut amount_of_current_nodes = self.og_data_vector_size;
            for level in 0..(self.og_data_vector_size as f64).sqrt().ceil() as usize + 1 as usize {
                // get the current level nodes
                let mut current_level: Vec<String> =
                    self.tree[level_start_index..level_end_index].to_vec();
                current_level.push(new_data.clone()); //push the new data
                let current_level_to_pow_2 =
                    extend_to_power2_size(&current_level.iter().map(String::as_str).collect()); //get the new nodes level
                if level != 0 {
                    computed_base = current_tree.clone();
                }
                current_tree = current_level_to_pow_2.clone();
                current_tree.append(&mut computed_base);
                level_end_index = level_start_index;
                amount_of_current_nodes /= 2;
                level_start_index = level_start_index - amount_of_current_nodes;
                new_data = digest(new_data.clone() + &new_data[..]); //calculate current level hash parent
            }
            new_data = digest(current_tree.get(0)?.to_owned() + current_tree.get(1)?); //calculate new root
            current_tree.insert(0, new_data);
            self.tree = current_tree;
            self.leaves_amount *= 2;
            self.last_data_index = self.last_data_index * 2 - 1;
        }
        self.og_data_vector_size += 1;
        Some(())
    }
}

///Extends the size of a vector to a power of 2 by repeating the last value.
fn extend_to_power2_size(vec: &Vec<&str>) -> Vec<String> {
    let mut copy: Vec<String> = vec.iter().map(|s| s.to_string()).collect();
    if !is_power_of_2(vec.len()) {
        let new_size = (2 as i32).pow(((vec.len() as f64).log2()).ceil() as u32); // ((vec.len() as f64).log2()).ceil() is an operation to get the biggest power of 2 exponent smaller than vec.len()
        for _ in 0..(new_size as usize) - vec.len() {
            copy.push(vec[vec.len() - 1].to_string());
        }
    }
    copy
}

fn is_power_of_2(num: usize) -> bool {
    num & (num - 1) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    fn merkle_tree_4_leaves_setup() -> MerkleTree {
        let vector = vec!["1", "2", "3", "4"];
        MerkleTree::new(vector)
    }

    fn merkle_tree_5_data_8_leaves_setup() -> MerkleTree {
        let vector = vec!["1", "2", "3", "4", "5"];
        MerkleTree::new(vector)
    }

    fn merkle_tree_8_leaves_setup() -> MerkleTree {
        let vector = vec!["1", "2", "3", "4", "5", "6", "7", "8"];
        MerkleTree::new(vector)
    }

    #[test]
    fn new_merkle_tree_of_4_leaves() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash2 = digest("2"); //idx 4
        let hash3 = digest("3"); //idx 5
        let hash4 = digest("4"); //idx 6

        let hash_leaves = vec![hash1, hash2, hash3, hash4];
        assert_eq!(merkle_tree.last_data_index, 6);
        assert_eq!(merkle_tree.tree[3..], hash_leaves);
    }

    #[test]
    fn new_merkle_tree_of_8_leaves() {
        let merkle_tree = merkle_tree_8_leaves_setup();

        let hash1 = digest("1"); //idx 7
        let hash2 = digest("2"); //idx 8
        let hash3 = digest("3"); //idx 9
        let hash4 = digest("4"); //idx 10

        let hash5 = digest("5"); //idx 11
        let hash6 = digest("6"); //idx 12
        let hash7 = digest("7"); //idx 13
        let hash8 = digest("8"); //idx 14

        let hash12 = digest(hash1.clone() + &hash2);
        let hash34 = digest(hash3.clone() + &hash4);
        let hash56 = digest(hash5.clone() + &hash6);
        let hash78 = digest(hash7.clone() + &hash8);

        let hash1234 = digest(hash12.clone() + &hash34);
        let hash5678 = digest(hash56.clone() + &hash78);

        let root = digest(hash1234.clone() + &hash5678);

        let tree = vec![
            root, hash1234, hash5678, hash12, hash34, hash56, hash78, hash1, hash2, hash3, hash4,
            hash5, hash6, hash7, hash8,
        ];
        assert_eq!(merkle_tree.last_data_index, 14);
        assert_eq!(merkle_tree.tree, tree);
    }

    #[test]
    fn new_merkle_tree_of_5_data_8_leaves() {
        let merkle_tree = merkle_tree_5_data_8_leaves_setup();

        let hash1 = digest("1"); //idx 7
        let hash2 = digest("2"); //idx 8
        let hash3 = digest("3"); //idx 9
        let hash4 = digest("4"); //idx 10

        let hash5 = digest("5"); //idx 11..14

        let hash12 = digest(hash1.clone() + &hash2);
        let hash34 = digest(hash3.clone() + &hash4);
        let hash55 = digest(hash5.clone() + &hash5);

        let hash1234 = digest(hash12.clone() + &hash34);
        let hash5555 = digest(hash55.clone() + &hash55);

        let root = digest(hash1234.clone() + &hash5555);

        let tree = vec![
            root,
            hash1234,
            hash5555,
            hash12,
            hash34,
            hash55.clone(),
            hash55.clone(),
            hash1,
            hash2,
            hash3,
            hash4,
            hash5.clone(),
            hash5.clone(),
            hash5.clone(),
            hash5.clone(),
        ];
        assert_eq!(merkle_tree.last_data_index, 11);
        assert_eq!(merkle_tree.tree, tree);
    }

    #[test]
    fn verify_correct_proof_with_even_leaf_index() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash3 = digest("3"); //idx 5
        let hash4 = digest("4"); //idx 6

        let hash34 = digest(hash3 + &hash4);
        let proof: Vec<String> = vec![hash1, hash34];
        assert!(merkle_tree.verify(proof, 4).unwrap());
    }

    #[test]
    fn verify_correct_proof_with_odd_leaf_index() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash2 = digest("2"); //idx 4
        let hash4 = digest("4"); //idx 6

        let hash12 = digest(hash1 + &hash2);
        let proof: Vec<String> = vec![hash4, hash12];
        assert!(merkle_tree.verify(proof, 5).unwrap());
    }

    #[test]
    fn verify_incorrect_proof() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash4 = digest("4"); //idx 6

        let proof: Vec<String> = vec![hash4, hash1];
        assert!(!merkle_tree.verify(proof, 5).unwrap());
    }

    #[test]
    fn verify_incorrect_proof_with_noise() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash3 = digest("3"); //idx 5
        let hash4 = digest("4"); //idx 6

        let hash34 = digest(hash3 + &hash4) + &"RUIDO";
        let proof: Vec<String> = vec![hash1, hash34];
        assert!(!merkle_tree.verify(proof, 4).unwrap());
    }

    #[test]
    fn verify_with_odd_leaf_index_8leaves_tree() {
        let merkle_tree = merkle_tree_8_leaves_setup();

        let hash1 = digest("1"); //idx 7
        let hash2 = digest("2"); //idx 8
        let hash3 = digest("3"); //idx 9
        let hash4 = digest("4"); //idx 10

        let hash12 = digest(hash1 + &hash2);
        let hash34 = digest(hash3 + &hash4);

        let hash1234 = digest(hash12 + &hash34);

        let hash6 = digest("6"); //idx 12

        let hash7 = digest("7"); //idx 13
        let hash8 = digest("8"); //idx 14

        let hash78 = digest(hash7 + &hash8);

        let proof: Vec<String> = vec![hash6, hash78, hash1234];
        assert!(merkle_tree.verify(proof, 11).unwrap());
    }

    #[test]
    fn verify_with_odd_leaf_tree_of_5_data_8_leaves() {
        let merkle_tree = merkle_tree_5_data_8_leaves_setup();

        let hash1 = digest("1"); //idx 7
        let hash2 = digest("2"); //idx 8
        let hash3 = digest("3"); //idx 9
        let hash4 = digest("4"); //idx 10

        let hash5 = digest("5"); //idx 11..14

        let hash12 = digest(hash1.clone() + &hash2);
        let hash34 = digest(hash3.clone() + &hash4);
        let hash55 = digest(hash5.clone() + &hash5);

        let hash1234 = digest(hash12.clone() + &hash34);

        let proof = vec![hash5, hash55, hash1234];
        assert!(merkle_tree.verify(proof, 11).unwrap());
    }

    #[test]
    fn generate_proof_with_even_leaf_index() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash3 = digest("3"); //idx 5
        let hash4 = digest("4"); //idx 6

        let hash34 = digest(hash3 + &hash4);
        let proof: Vec<String> = vec![hash1, hash34];
        assert_eq!(merkle_tree.generate_proof(4).unwrap(), proof);
    }

    #[test]
    fn generate_proof_with_odd_leaf_index() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash2 = digest("2"); //idx 4
        let hash4 = digest("4"); //idx 6

        let hash12 = digest(hash1 + &hash2);
        let proof: Vec<String> = vec![hash4, hash12];
        assert_eq!(merkle_tree.generate_proof(5).unwrap(), proof);
    }

    #[test]
    fn generate_proof_with_odd_leaf_index_8leaves_tree() {
        let merkle_tree = merkle_tree_8_leaves_setup();

        let hash1 = digest("1"); //idx 7
        let hash2 = digest("2"); //idx 8
        let hash3 = digest("3"); //idx 9
        let hash4 = digest("4"); //idx 10

        let hash12 = digest(hash1 + &hash2);
        let hash34 = digest(hash3 + &hash4);

        let hash1234 = digest(hash12 + &hash34);

        let hash6 = digest("6"); //idx 12

        let hash7 = digest("7"); //idx 13
        let hash8 = digest("8"); //idx 14

        let hash78 = digest(hash7 + &hash8);

        let proof: Vec<String> = vec![hash6, hash78, hash1234];
        assert_eq!(merkle_tree.generate_proof(11).unwrap(), proof);
    }

    #[test]
    fn generate_proof_with_odd_leaf_tree_of_5_data_8_leaves() {
        let merkle_tree = merkle_tree_5_data_8_leaves_setup();

        let hash1 = digest("1"); //idx 7
        let hash2 = digest("2"); //idx 8
        let hash3 = digest("3"); //idx 9
        let hash4 = digest("4"); //idx 10

        let hash5 = digest("5"); //idx 11..14

        let hash12 = digest(hash1.clone() + &hash2);
        let hash34 = digest(hash3.clone() + &hash4);
        let hash55 = digest(hash5.clone() + &hash5);

        let hash1234 = digest(hash12.clone() + &hash34);

        let proof = vec![hash5, hash55, hash1234];
        assert_eq!(merkle_tree.generate_proof(11).unwrap(), proof);
    }

    #[test]
    fn test_extend_to_power2_size() {
        let vector = vec!["1", "2", "3", "4"];
        let vector_extended = extend_to_power2_size(&vector);
        assert_eq!(vector_extended, vec!["1", "2", "3", "4"]);

        let vector = vec!["1", "2", "3"];
        let vector_extended = extend_to_power2_size(&vector);
        assert_eq!(vector_extended, vec!["1", "2", "3", "3"]);

        let vector = vec!["1", "2", "3", "4", "5"];
        let vector_extended = extend_to_power2_size(&vector);
        assert_eq!(
            vector_extended,
            vec!["1", "2", "3", "4", "5", "5", "5", "5"]
        );
    }

    #[test]
    fn add_node_and_verify_proof_with_odd_leaf_tree_of_5_data_8_leaves() {
        let mut merkle_tree = merkle_tree_4_leaves_setup();
        merkle_tree.add_node("5");
        let hash1 = digest("1"); //idx 7
        let hash2 = digest("2"); //idx 8
        let hash3 = digest("3"); //idx 9
        let hash4 = digest("4"); //idx 10

        let hash5 = digest("5"); //idx 11..14

        let hash12 = digest(hash1.clone() + &hash2);
        let hash34 = digest(hash3.clone() + &hash4);
        let hash55 = digest(hash5.clone() + &hash5);

        let hash1234 = digest(hash12.clone() + &hash34);

        let proof = vec![hash5, hash55, hash1234];
        assert!(merkle_tree.verify(proof, 11).unwrap());
    }

    #[test]
    fn add_node_and_verify_proof_with_even_leaf_tree_of_6_data_8_leaves() {
        let mut merkle_tree = merkle_tree_4_leaves_setup();
        merkle_tree.add_node("5");
        merkle_tree.add_node("6");
        let hash1 = digest("1"); //idx 7
        let hash2 = digest("2"); //idx 8
        let hash3 = digest("3"); //idx 9
        let hash4 = digest("4"); //idx 10

        let hash5 = digest("5"); //idx 11
        let hash6 = digest("6"); //idx 12..14

        let hash12 = digest(hash1.clone() + &hash2);
        let hash34 = digest(hash3.clone() + &hash4);
        let hash66 = digest(hash6.clone() + &hash6);

        let hash1234 = digest(hash12.clone() + &hash34);

        let proof = vec![hash5, hash66, hash1234];
        assert!(merkle_tree.verify(proof, 12).unwrap());
    }
}
