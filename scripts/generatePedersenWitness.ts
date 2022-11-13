import { randomBytes } from 'crypto';
import { Schnorr } from '@noir-lang/barretenberg/dest/crypto';
import { writeFileSync } from 'fs';
import { BarretenbergWasm } from '@noir-lang/barretenberg/dest/wasm';
import { MerkleTree } from '../utils/MerkleTree';
// import { StandardMerkleTree } from '@openzeppelin/merkle-tree';
import { SinglePedersen } from '@noir-lang/barretenberg/dest/crypto/pedersen';
import { stringify } from '@iarna/toml';

const main = async () => {

  const EXISTING_MEMBERS = 2;
  const barretenberg = await BarretenbergWasm.new();
  const daoTree = new MerkleTree(3, barretenberg);
  const pedersen = new SinglePedersen(barretenberg);
  const shcnorr = new Schnorr(barretenberg);
  const userPrivateKeys = new Array(EXISTING_MEMBERS).fill('').map(_ => randomBytes(32));

  const createHashPath = (merkleProof) => {
    return merkleProof.pathElements.map(el => {
      if (typeof el === 'string') {
        return `0x${el}`;
      }
      else {
        return `0x${Buffer.from(el).toString('hex')}`;
      }
    })
  }

  const createMemberCommitments = (privateKeys: Uint8Array[]) => {
    return privateKeys.map(key => {
      const pubKey = shcnorr.computePublicKey(key);
      const pubKey_x = pubKey.subarray(0, 32);
      const pubKey_y = pubKey.subarray(32);
      return pedersen.compressInputs([pubKey_x, pubKey_y]);
    });
  }

  const generateWitness = async () => {
    const commitments = createMemberCommitments(userPrivateKeys);
    commitments.forEach((cmt: Buffer) => {
      daoTree.insert(cmt.toString('hex'));
    })

    const merkleProof = daoTree.proof(0);
    const witness = {
      daoRoot: `0x${daoTree.root()}`,
      daoPath: createHashPath(merkleProof),
      index: 0,
      // First private key generated
      privKey: `0x${userPrivateKeys[0].toString('hex')}`
    }
    writeFileSync('../circuits/Prover.toml', stringify(witness));
    console.log('Witness written to circuits/Prover.toml');
    const verifierContent = {
      setpub: [],
      daoRoot: witness.daoRoot
    }
    writeFileSync('../circuits/Verifier.toml', stringify(verifierContent));
    console.log('Verifier written to circuits/Verifier.toml');
  };

  generateWitness();
}

main();
