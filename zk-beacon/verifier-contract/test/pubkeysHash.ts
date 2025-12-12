import * as fs from "fs";
import * as path from "path";
import {projectRoot} from "./utils.ts";
import { ethers } from "ethers";

/**
 * JSON 파일에서 48-byte hex string 512개를 읽어
 * 하나의 Uint8Array(총 24576 bytes)로 변환한다.
 *
 * JSON 구조는:
 * - 최상위가 string[] 이거나
 * - { pubkeys: string[] } 둘 다 지원하도록 작성.
 */
interface PubkeysJson {
    pubkeys: string[];
}

function loadCurrSc(path: string) {
    
}

export async function putkeysHash(jsonPath: string) {
    const raw = fs.readFileSync(path.resolve(jsonPath), "utf8");
    const parsed = JSON.parse(raw) as PubkeysJson | string[];

    // pubkey 배열 가져오기
    const hexArray: string[] = Array.isArray(parsed)
        ? parsed
        : parsed.pubkeys;

    if (!Array.isArray(hexArray)) {
        throw new Error("Invalid JSON format: expected string[] or { pubkeys: string[] }");
    }
    if (hexArray.length !== 512) {
        throw new Error(`Expected 512 entries, got ${hexArray.length}`);
    }

    // 최종 길이: 512 * 48 bytes = 24576
    const pubkeys = new Uint8Array(512 * 48);
    let offset = 0;

    hexArray.forEach((hex, index) => {
        if (typeof hex !== "string") {
            throw new Error(`Entry #${index} is not a string`);
        }

        // "0x" 프리픽스 제거
        const clean = hex.startsWith("0x") ? hex.slice(2) : hex;

        // 48 bytes = 96 hex chars
        if (clean.length !== 96) {
            throw new Error(`Entry #${index} has invalid length: ${clean.length} (expected 96 hex chars)`);
        }

        for (let i = 0; i < clean.length; i += 2) {
            const byteStr = clean.slice(i, i + 2);
            const byte = Number.parseInt(byteStr, 16);
            if (Number.isNaN(byte)) {
                throw new Error(`Entry #${index} contains invalid hex: "${byteStr}"`);
            }
            pubkeys[offset++] = byte;
        }
    });

    // Create provider
    const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545/");
    const lightClientArtifact = JSON.parse(
        fs.readFileSync(
            path.join(projectRoot(), "/artifacts/contracts/LightClient.sol/LightClient.json"),
            "utf8"
        )
    );

// Create contract instance
    const lightClient = new ethers.Contract(
        "0xe815357a70887f28ae1ac3D669E5404e6DcEc981",
        lightClientArtifact.abi,
        provider
    );

    console.log("pubkeys length:", pubkeys.length)
    const ret = await lightClient.testPubKeysHash(pubkeys, {
        gasLimit: 30000000  // Poseidon 해시 512개 처리
    });
    return ret;
}

// 사용 예시
async function main() {
    const hashBytes = await putkeysHash(`${projectRoot()}/../data/curr-sc.json`);
    console.log("hashBytes:", hashBytes); // 24576
}

main().catch(console.error);
