use dep::std;

fn main(
  // Merkle membership proof
  daoRoot: pub Field, 
  daoPath: [Field; 3],
  index: Field,
  // Private key of note
  privKey: Field, 
  // Random secret to keep note_commitment private
  // secret: Field
) {
    // Compute public key from private key to show ownership
    let pubkey = std::scalar_mul::fixed_base(privKey);
    let pubkey_x = pubkey[0];
    let pubkey_y = pubkey[1];
    
    // Compute input note commitment
    // let note_commitment = std::hash::pedersen([pubkey_x, pubkey_y, secret]);
    let note_commitment = std::hash::pedersen([pubkey_x, pubkey_y]);

    // Check that the input note commitment is in the root
    let is_member = std::merkle::check_membership(daoRoot, note_commitment[0], index, daoPath);
    constrain is_member == 1;
}