use std::hash::{DefaultHasher, Hash, Hasher};

struct Merkle_Tree{
    hasher:DefaultHasher,
    root:u64,
    tree: Vec<u64>,
}
/* */
impl Merkle_Tree {


    fn verify(&self,proof:Vec<u64>,mut leaf_index:usize) -> bool{
        let mut hasher = &self.hasher;
        let mut hash_for_verification:u64 = self.tree[leaf_index];
        for i in 0..proof.len(){
            if leaf_index % 2 == 0 {
                (hash_for_verification,proof[i]).hash(&mut hasher);
                hash_for_verification = hasher.finish();
            } else {
                (proof[i],hash_for_verification).hash(&mut hasher);
                hash_for_verification = hasher.finish();
            }
            leaf_index = leaf_index/2;
        }
        println!("root calculado: {}",hash_for_verification);
        println!("root og: {} ",self.root);
        hash_for_verification == self.root
    }
}


fn main() {
    let mut tree_hasher = DefaultHasher::new();
    let vector = [1,2,3,4];
    let mut leaves = vec![];
    for data in vector{
        data.hash(&mut tree_hasher);
        leaves.push(tree_hasher.finish());
    }

    let mut level_1_branches =  vec![];
    for i in (0..leaves.len()).step_by(2) {
        (leaves[i],leaves[i+1]).hash(&mut tree_hasher);
        level_1_branches.push(tree_hasher.finish());
    }

    level_1_branches.append(&mut leaves);
    (level_1_branches[0],level_1_branches[1]).hash(&mut tree_hasher);

    let merkle_tree = Merkle_Tree{
        hasher: tree_hasher,
        root: tree_hasher.finish(),
        tree: level_1_branches.clone(),
    };

    let proof: Vec<u64> = vec![2]; 

    let a = merkle_tree.verify(proof,2);  
    println!("{}",a);  

    println!("{:?}",merkle_tree.tree);  
    
    //h1, h2,  1, 2, 3, 4
    let proof: Vec<u64> = vec![level_1_branches[2],level_1_branches[1]]; 
    println!("{}",level_1_branches[2]);  
    println!("{}",level_1_branches[1]);  

    let b = merkle_tree.verify(proof,3);  
    println!("{}",b);  
}