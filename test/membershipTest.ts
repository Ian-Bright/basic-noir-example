import { BarretenbergWasm } from '@noir-lang/barretenberg/dest/wasm';
import { create_proof, setup_generic_prover_and_verifier, verify_proof } from '@noir-lang/barretenberg/dest/client_proofs';
import { expect } from 'chai';
import { randomBytes } from 'crypto'
import { readFileSync } from 'fs';
import { MerkleTree } from '../utils/MerkleTree';
import { acir_from_bytes } from '@noir-lang/noir_wasm';
import { resolve } from 'path';
import { Schnorr, SinglePedersen } from '@noir-lang/barretenberg/dest/crypto';

let barretenberg: BarretenbergWasm;
let pedersen: SinglePedersen;
let schnorr: Schnorr;
let tree: MerkleTree;

before(async () => {
    barretenberg = await BarretenbergWasm.new();
    pedersen = new SinglePedersen(barretenberg);
    schnorr = new Schnorr(barretenberg);
    tree = new MerkleTree(3, barretenberg);
});

describe('Test membership in group using acir from file', () => {
    it('Should pass with correct private key', async () => {
        let acirByteArray = path_to_uint8array(resolve(__dirname, `../circuits/build/test.acir`));
        let acir = acir_from_bytes(acirByteArray);
        const privKeys = createPrivKeys(3);
        const commitments = createMemberCommitments(privKeys);
        commitments.forEach(cmt => {
            tree.insert(cmt);
        });
        const merkleProof = tree.proof(0);
        let abi = {
            daoRoot: `0x${tree.root()}`,
            daoPath: createHashPath(merkleProof),
            index: 0,
            privKey: `0x${Buffer.from(privKeys[0]).toString('hex')}`
        };

        const [prover, verifier] = await setup_generic_prover_and_verifier(acir);

        const proof = await create_proof(prover, acir, abi);

        const verified = await verify_proof(verifier, proof);

        expect(verified).eq(true);
    });

    xit('Should pass with correct private key', async () => {
        let acirByteArray = path_to_uint8array(resolve(__dirname, `../circuits/build/test.acir`));
        let acir = acir_from_bytes(acirByteArray);
        const privKeys = createPrivKeys(3);
        const commitments = createMemberCommitments(privKeys);
        commitments.forEach(cmt => {
            tree.insert(cmt);
        });
        const merkleProof = tree.proof(3);
        let abi = {
            daoPath: createHashPath(merkleProof),
            daoRoot: formatHex(tree.root()),
            index: 3,
            privKey: formatHex(Buffer.from(privKeys[0]).toString('hex'))
        };

        const [prover, verifier] = await setup_generic_prover_and_verifier(acir);

        const proof = await create_proof(prover, acir, abi);

        const verified = await verify_proof(verifier, proof);

        expect(verified).eq(true);
    });
})

const createMemberCommitments = (privateKeys: Uint8Array[]) => {
    return privateKeys.map(key => {
        const pubKey = schnorr.computePublicKey(key);
        const pubKey_x = pubKey.subarray(0, 32);
        const pubKey_y = pubKey.subarray(32);
        return pedersen.compressInputs([pubKey_x, pubKey_y]).toString('hex');
    });
}

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

const createPrivKeys = (users: number) => {
    return new Array(users).fill(0).map(_ => randomBytes(32));
}

const formatHex = (str: string) => {
    return `0x${str}`;
}

const path_to_uint8array = (path: string) => {
    let buffer = readFileSync(path);
    return new Uint8Array(buffer);
}