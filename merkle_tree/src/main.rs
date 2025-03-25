use sha256::digest;

struct Merkle_Tree{
    tree: Vec<String>,
    leaves : usize,
}
/* */
impl Merkle_Tree {
    /// Given a proof and an index of a data hash the function must determine wether the proof is correct.
    /// For understanding this function we can consider the following tree:
    ///               root
    ///          h12        h34 
    ///        h1   h2    h3   h4
    ///        |    |     |     |
    ///     data1 data2 data3 data4
    /// The array representation would be: [root,h12,h34,h1,h2,h3,h4]
    /// With the indexes                     0   1   2   3  4  5   6
    fn verify(&self,proofs:Vec<String>,mut leaf_index:usize) -> bool{
        let mut hash_for_verification = self.tree[leaf_index].clone();
        for proof in proofs{
            if leaf_index % 2 == 1 { // if index is odd we are on a left branch, so the verification must be computed concatenating the proof second
                hash_for_verification = digest(hash_for_verification.to_owned()+&proof);
            } else { // if index is even we are on a right branch, so the verification must be computed concatenating the proof first
                hash_for_verification = digest(proof.clone()+&hash_for_verification);
                leaf_index-=1; //if it's a right child this is necesary to calculate its parent
            }
            leaf_index = leaf_index/2;
        }
        hash_for_verification == self.tree[0]
    }

    /// Builds the tree concatenating the diferent levels into one array.
    /// Te final array tree goes from root to leaves -> [root....branch_n, branch_n+1....leaf].
    fn new(data_vector:Vec<&str>)->Self{
        let mut level_n = vec![];
        for data in &data_vector{
            level_n.push(digest(*data));
        }
        let mut current_tree = vec![];
        for level in 0.. data_vector.len()/2{ //Amount of levels
            let mut level_n_minus1 = vec![];
            for i in (0..level_n.len()).step_by(2) { //Build new level from the previous one
                level_n_minus1.push(digest(level_n[i].clone()+ &level_n[i+1]));
            }
            let next_current_level = level_n_minus1.clone();
            if level == 0{
                level_n_minus1.append(&mut level_n); //Concatenating the leaves.
            }else{
                level_n_minus1.append(&mut current_tree); //Concatenating the previous levels.
            }
            current_tree = level_n_minus1.clone();
            level_n = next_current_level;
        }
    
        Self{
            tree: current_tree.clone(),
            leaves: data_vector.len(),
        }
    }
}


fn main() {
    
}


#[cfg(test)]
mod tests {
    use super::*;
    fn merkle_tree_4_leaves_setup()->Merkle_Tree{
        let vector = vec!["1","2","3","4"];
        Merkle_Tree::new(vector)
    }

    #[test]
    fn new_merkle_tree_of_4_leaves() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash2 = digest("2"); //idx 4
        let hash3 = digest("3"); //idx 5
        let hash4 = digest("4"); //idx 6
        
        let hash_leaves = vec![hash1,hash2,hash3,hash4];
        assert_eq!(merkle_tree.leaves,4);
        assert_eq!(merkle_tree.tree[3..],hash_leaves);
    }

    #[test]
    fn verify_correct_proof_with_even_leaf_index() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash3 = digest("3"); //idx 5
        let hash4 = digest("4"); //idx 6
 
        let hash34 = digest(hash3 + &hash4);
        let proof: Vec<String> = vec![hash1,hash34]; 
        assert!(merkle_tree.verify(proof,4));
    }

    #[test]
    fn verify_correct_proof_with_odd_leaf_index() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash2 = digest("2"); //idx 4
        let hash4 = digest("4"); //idx 6
 
        let hash12 = digest(hash1 + &hash2);
        let proof: Vec<String> = vec![hash4,hash12]; 
        assert!(merkle_tree.verify(proof,5));
    }

    #[test]
    fn verify_incorrect_proof() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash4 = digest("4"); //idx 6
 
        let proof: Vec<String> = vec![hash4,hash1]; 
        assert!(!merkle_tree.verify(proof,5));
    }

    #[test]
    fn verify_incorrect_proof_with_noise() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash3 = digest("3"); //idx 5
        let hash4 = digest("4"); //idx 6
 
        let hash34 = digest(hash3 + &hash4)+&"RUIDO";
        let proof: Vec<String> = vec![hash1,hash34]; 
        assert!(!merkle_tree.verify(proof,4));
    }

}