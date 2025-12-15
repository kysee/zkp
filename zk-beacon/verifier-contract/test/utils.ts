import * as fs from 'fs';
import path from 'path';

export function projectRoot(startPath = "."): string {
    let currentPath = startPath;

    while (currentPath !==
    path.parse(currentPath).root) {
        if (fs.existsSync(path.join(currentPath,
            'package.json'))) {
            return currentPath;
        }
        currentPath = path.dirname(currentPath);
    }

    throw new Error('not found project root dir');
}

export interface SyncCommittee {
    aggregate_pubkey: string;
    pubkeys: string[];
}

export function loadSyncCommittee(dataPath:string): SyncCommittee {
    const fileContent = fs.readFileSync(dataPath, 'utf8');
    const jsonData = JSON.parse(fileContent);
    if(jsonData.data) {
        return jsonData.data.next_sync_committee;
    }
    return jsonData;
}

/**
 * SyncCommittee의 pubkeys만 바이트로 변환한다.
 * pubkeys: 512 * 48 bytes = 24576 bytes
 */
export function syncCommitteePubkeysToBytes(sc: SyncCommittee): Uint8Array {
    const pubkeys = sc.pubkeys;

    if (pubkeys.length !== 512) {
        throw new Error(`Expected 512 pubkeys, got ${pubkeys.length}`);
    }

    // 총 길이: 512 * 48 = 24576 bytes
    const result = new Uint8Array(512 * 48);
    let offset = 0;

    // pubkeys 512개를 변환
    pubkeys.forEach((hex, index) => {
        if (typeof hex !== "string") {
            throw new Error(`Pubkey #${index} is not a string`);
        }

        const clean = hex.startsWith("0x") ? hex.slice(2) : hex;

        // 48 bytes = 96 hex chars
        if (clean.length !== 96) {
            throw new Error(`Pubkey #${index} has invalid length: ${clean.length} (expected 96 hex chars)`);
        }

        for (let i = 0; i < clean.length; i += 2) {
            const byteStr = clean.slice(i, i + 2);
            const byte = Number.parseInt(byteStr, 16);
            if (Number.isNaN(byte)) {
                throw new Error(`Pubkey #${index} contains invalid hex: "${byteStr}"`);
            }
            result[offset++] = byte;
        }
    });

    return result;
}

/**
 * NextSyncCommittee의 pubkeys와 aggregate_pubkey를 바이트로 변환 후 이어붙인다.
 * pubkeys: 512 * 48 bytes = 24576 bytes
 * aggregate_pubkey: 48 bytes
 * 총 24624 bytes
 */
export function syncCommitteeToBytes(sc: SyncCommittee): Uint8Array {
    const pubkeys = sc.pubkeys;
    const aggregatePubkey = sc.aggregate_pubkey;

    if (pubkeys.length !== 512) {
        throw new Error(`Expected 512 pubkeys, got ${pubkeys.length}`);
    }

    // total length: 512 * 48 + 48 = 24624 bytes
    const result = new Uint8Array(512 * 48 + 48);
    let offset = 0;

    // pubkeys 512개를 변환
    pubkeys.forEach((hex, index) => {
        if (typeof hex !== "string") {
            throw new Error(`Pubkey #${index} is not a string`);
        }

        const clean = hex.startsWith("0x") ? hex.slice(2) : hex;

        // 48 bytes = 96 hex chars
        if (clean.length !== 96) {
            throw new Error(`Pubkey #${index} has invalid length: ${clean.length} (expected 96 hex chars)`);
        }

        for (let i = 0; i < clean.length; i += 2) {
            const byteStr = clean.slice(i, i + 2);
            const byte = Number.parseInt(byteStr, 16);
            if (Number.isNaN(byte)) {
                throw new Error(`Pubkey #${index} contains invalid hex: "${byteStr}"`);
            }
            result[offset++] = byte;
        }
    });

    // aggregate_pubkey 변환
    if (typeof aggregatePubkey !== "string") {
        throw new Error("aggregate_pubkey is not a string");
    }

    const cleanAggregate = aggregatePubkey.startsWith("0x") ? aggregatePubkey.slice(2) : aggregatePubkey;

    if (cleanAggregate.length !== 96) {
        throw new Error(`aggregate_pubkey has invalid length: ${cleanAggregate.length} (expected 96 hex chars)`);
    }

    for (let i = 0; i < cleanAggregate.length; i += 2) {
        const byteStr = cleanAggregate.slice(i, i + 2);
        const byte = Number.parseInt(byteStr, 16);
        if (Number.isNaN(byte)) {
            throw new Error(`aggregate_pubkey contains invalid hex: "${byteStr}"`);
        }
        result[offset++] = byte;
    }

    return result;
}

export interface ProofData {
    proof: string[];
    commitments: string[];
    commitmentPok: string[];
}

/**
 * Load proof data from JSON file
 * @param dataPath Path to proof.json file
 * @returns ProofData object containing proof, commitments, and commitmentPok
 */
export function loadProof(dataPath: string): ProofData {
    const fileContent = fs.readFileSync(dataPath, 'utf8');
    const jsonData = JSON.parse(fileContent);

    if (!jsonData.proof || !Array.isArray(jsonData.proof)) {
        throw new Error('Invalid proof.json: proof must be an array');
    }

    if (!jsonData.commitments || !Array.isArray(jsonData.commitments)) {
        throw new Error('Invalid proof.json: commitments must be an array');
    }

    if (!jsonData.commitmentPok || !Array.isArray(jsonData.commitmentPok)) {
        throw new Error('Invalid proof.json: commitmentPok must be an array');
    }

    if (jsonData.proof.length !== 8) {
        throw new Error(`Invalid proof.json: proof must have 8 elements, got ${jsonData.proof.length}`);
    }

    if (jsonData.commitments.length !== 2) {
        throw new Error(`Invalid proof.json: commitments must have 2 elements, got ${jsonData.commitments.length}`);
    }

    if (jsonData.commitmentPok.length !== 2) {
        throw new Error(`Invalid proof.json: commitmentPok must have 2 elements, got ${jsonData.commitmentPok.length}`);
    }

    return {
        proof: jsonData.proof,
        commitments: jsonData.commitments,
        commitmentPok: jsonData.commitmentPok
    };
}

