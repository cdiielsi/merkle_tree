use sha256::digest;

struct Merkle_Tree{
    root:String,
    tree: Vec<String>,
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
        hash_for_verification == self.root
    }
}


fn main() {
    let merkle_tree = merkle_tree_4_leaves_setup();

    let hash1 = digest("1"); //idx 3
    let hash2 = digest("2"); //idx 4
    let hash3 = digest("3"); //idx 5
    let hash4 = digest("4"); //idx 6

    let hash12: String = digest(hash1.clone() + &hash2);
    let hash34 = digest(hash3 + &hash4);

    let proof1: Vec<String> = vec![hash1,hash34]; 
    println!("Verification result = {}",merkle_tree.verify(proof1,4));  

    let proof2: Vec<String> = vec![hash4,hash12]; 
    println!("Verification result = {}",merkle_tree.verify(proof2,5));  

}


fn merkle_tree_4_leaves_setup()->Merkle_Tree{
    let vector = ["1","2","3","4"];
    let mut leaves = vec![];
    for data in vector{
        leaves.push(digest(data));
    }
    let mut level_1_branches =  vec![];
    for i in (0..leaves.len()).step_by(2) {
        level_1_branches.push(digest(leaves[i].clone()+ &leaves[i+1]));
    }
    level_1_branches.append(&mut leaves); //Concatenating the leaves.

    let mut final_tree = vec![];
    final_tree.push(digest(level_1_branches[0].clone()+ &level_1_branches[1]));
    final_tree.append(&mut level_1_branches.clone());

    Merkle_Tree{
        root: final_tree[0].clone(),
        tree: final_tree.clone(),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

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