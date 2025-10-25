
import Web3 from '@beatoz/web3';
import * as fs from 'fs';
import path from 'path';

export function projectRoot(startPath = __dirname): string {
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

export function fromFile(path: string) {
    try {
        const buf = fs.readFileSync(path, 'utf-8');
        return JSON.parse(buf);
    } catch (e) {
        console.error(e);
        process.exit(0);
    }
}

export function chainConfig(chainAlias: string) {
    return fromFile(`${projectRoot()}/scripts/beatoz/config.${chainAlias}.json`);
}

export function deployedInfo(chainAlias: string, contractAlias: string) {
    return fromFile(`${projectRoot()}/scripts/beatoz/deployed.${chainAlias}.${contractAlias}.json`);
}

export function contractABI(contractAlias: string) {
    return fromFile(`${projectRoot()}/artifacts/contracts/${contractAlias}.sol/${contractAlias}.json`);
}



// Base64 to hex string conversion
export function base64ToHex(base64: string): string {
    const buffer = Buffer.from(base64, 'base64');
    return buffer.toString('hex');
}

// Hex string to base64 conversion
export function hexToBase64(hex: string): string {
    const buffer = Buffer.from(hex, 'hex');
    return buffer.toString('base64');
}

export function findAbiInput(abis: any[], method?: string) {
    const _method = method ?? 'constructor'
    for (const abi of abis) {
        if (abi.type === 'constructor' && abi.type === _method) {
            return abi.inputs;
        }
        else if (abi.name === _method) {
            return abi.inputs
        }
    }
    return null;
}

export function parseTxCommitResult(txCommit: any): string | null {
    if (txCommit.check_tx.code != 0) {
        const log = txCommit.check_tx.log;
        const data = txCommit.check_tx.data;
        let errMsg = "";
        if (data && log.includes('revert')) {
            errMsg = Buffer.from(data, 'base64').toString('hex');
        } else if (data) {
            console.error(data);
            errMsg = Buffer.from(data, 'base64').toString('utf-8');
        }

        return `error: check_tx(${txCommit.check_tx.code}) - ${log} (${errMsg})`;
    }
    if (txCommit.deliver_tx.code != 0) {
        const log = txCommit.deliver_tx.log;
        const data = txCommit.deliver_tx.data;
        let errMsg: string | null = "";
        if (data && log.includes('revert')) {
            errMsg = _parseEvmCallError(Buffer.from(data, 'base64').toString('hex'), new Web3());
        } else if (data) {
            console.error(data);
            errMsg = Buffer.from(data, 'base64').toString('utf-8');
        }
        return `error: deliver_tx(${txCommit.deliver_tx.code}) - ${log} (${errMsg})`;
    }
    return null;
}

export function panicTxCommitResult(txCommit: any) {
    const ret = parseTxCommitResult(txCommit);
    if (ret) {
        throw new Error(ret);
    }
}


export function parseEvmCallError(ret: any, web3: Web3): string | null {
    if (ret.value.vmErr) {
        return _parseEvmCallError(ret.value.returnData, web3);
    }
    return null;
}

function _parseEvmCallError(err: string, web3: Web3): string | null {
    err = err.toLowerCase();
    if (err.startsWith('08c379a0')) {
        return web3.beatoz.abi.decodeParameter('string', err.slice(8)) as string;
    }
    return null;
}

export function panicEvmCallError(err: string, web3: Web3) {
    const ret = parseEvmCallError(err, web3);
    if (ret) {
        throw new Error(ret);
    }
}

export function sleep(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}