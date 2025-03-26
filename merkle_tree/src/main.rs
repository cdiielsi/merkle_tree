use sha256::digest;

struct Merkle_Tree{
    tree: Vec<String>,
    leaves : usize,
}
/* */
impl Merkle_Tree {
    /// Builds the tree concatenating the diferent levels into one array.
    /// Te final array tree goes from root to leaves -> [root....branch_n, branch_n+1....leaf].
    fn new(data_vector:Vec<&str>)->Self{
        let mut level_n = vec![];
        for data in &data_vector{
            level_n.push(digest(*data));
        }
        let mut current_tree = vec![];
        for level in 0..(data_vector.len() as f64).sqrt().ceil() as usize{ //Amount of levels
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

    /// Given an index of a data hash the function must return the proof that the tree contains that data hash.
    fn give_proof(&self,leaf_index:usize)-> Vec<String>{
        let mut index = leaf_index;
        let mut proof:Vec<String> = vec![];
        while index > 0 {
            if index % 2 == 1 { // if index is odd we are on a left branch, so the verification must be computed concatenating the proof second
                proof.push(self.tree[index+1].clone());
            } else { // if index is even we are on a right branch, so the verification must be computed concatenating the proof first
                proof.push(self.tree[index-1].clone());
                index-=1; //if it's a right child this is necesary to calculate its parent
            }
            index = index/2;
        }
        proof
    }
}


fn main() {
    let vector = vec!["1","2","3","4","5","6","7","8"];
    let merkle_tree = Merkle_Tree::new(vector);
    
}


#[cfg(test)]
mod tests {
    use super::*;
    fn merkle_tree_4_leaves_setup()->Merkle_Tree{
        let vector = vec!["1","2","3","4"];
        Merkle_Tree::new(vector)
    }

    fn merkle_tree_8_leaves_setup()->Merkle_Tree{
        let vector = vec!["1","2","3","4","5","6","7","8"];
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

        let tree = vec![root, hash1234, hash5678, hash12, hash34, hash56, hash78,hash1,hash2,hash3,hash4,hash5,hash6,hash7,hash8];
        //let hash_leaves = vec![hash1,hash2,hash3,hash4,hash5,hash6,hash7,hash8];
        assert_eq!(merkle_tree.leaves,8);
        //assert_eq!(merkle_tree.tree.len(),15);
        assert_eq!(merkle_tree.tree,tree);
        //assert_eq!(merkle_tree.tree[7..],hash_leaves);
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

    #[test]
    fn give_proof_with_even_leaf_index() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash3 = digest("3"); //idx 5
        let hash4 = digest("4"); //idx 6
 
        let hash34 = digest(hash3 + &hash4);
        let proof: Vec<String> = vec![hash1,hash34]; 
        assert_eq!(merkle_tree.give_proof(4),proof);
    }

    #[test]
    fn give_proof_with_odd_leaf_index() {
        let merkle_tree = merkle_tree_4_leaves_setup();

        let hash1 = digest("1"); //idx 3
        let hash2 = digest("2"); //idx 4
        let hash4 = digest("4"); //idx 6
 
        let hash12 = digest(hash1 + &hash2);
        let proof: Vec<String> = vec![hash4,hash12]; 
        assert_eq!(merkle_tree.give_proof(5),proof);
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

        let hash1234 =  digest(hash12 + &hash34);

        let hash6 = digest("6"); //idx 12

        let hash7 = digest("7"); //idx 13
        let hash8 = digest("8"); //idx 14

        let hash78 = digest(hash7 + &hash8);
 
        let proof: Vec<String> = vec![hash6,hash78,hash1234]; 
        assert!(merkle_tree.verify(proof,11));
    }


    #[test]
    fn give_proof_with_odd_leaf_index_8leaves_tree() {
        let merkle_tree = merkle_tree_8_leaves_setup();

        let hash1 = digest("1"); //idx 7
        let hash2 = digest("2"); //idx 8
        let hash3 = digest("3"); //idx 9
        let hash4 = digest("4"); //idx 10

        let hash12 = digest(hash1 + &hash2);
        let hash34 = digest(hash3 + &hash4);

        let hash1234 =  digest(hash12 + &hash34);

        let hash6 = digest("6"); //idx 12

        let hash7 = digest("7"); //idx 13
        let hash8 = digest("8"); //idx 14

        let hash78 = digest(hash7 + &hash8);
 
        let proof: Vec<String> = vec![hash6,hash78,hash1234]; 
        assert_eq!(merkle_tree.give_proof(11),proof);
    }

    #[test]
    fn give_incorrect_proof_with_odd_leaf_index_8leaves_tree() {
        let merkle_tree = merkle_tree_8_leaves_setup();

        let hash1 = digest("1"); //idx 7
        let hash2 = digest("2"); //idx 8
        let hash3 = digest("3"); //idx 9
        let hash4 = digest("4"); //idx 10

        let hash12 = digest(hash1 + &hash2);
        let hash34 = digest(hash3 + &hash4);

        let hash1234 =  digest(hash12 + &hash34);

        let hash6 = digest("6"); //idx 12

        let hash7 = digest("7"); //idx 13
        let hash8 = digest("8"); //idx 14

        let hash78 = digest(hash7 + &hash8);
 
        let proof: Vec<String> = vec![hash6,hash78,hash1234]; //This proof is the same as last test for the "5" data node
        assert_ne!(merkle_tree.give_proof(9),proof);
    }
}

