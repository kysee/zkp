
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

export function contractJson(contractAlias: string) {
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

export function panicTxCommitResult(txCommit: any) {
    const ret = parseTxCommitResult(txCommit);
    if (ret) {
        throw new Error(ret);
    }
}

export function parseTxCommitResult(txCommit: any): string | null {
    let step = "check_tx";
    let code = txCommit.check_tx.code;
    let log = txCommit.check_tx.log;
    let data = txCommit.check_tx.data;

    if (txCommit.deliver_tx.code != 0) {
        step = "deliver_tx";
        code = txCommit.deliver_tx.code;
        log = txCommit.deliver_tx.log;
        data = txCommit.deliver_tx.data;
    }

    if (code != 0) {
        let errMsg: string | null  = null;
        if (data && log.includes('revert')) {
            errMsg = Buffer.from(data, 'base64').toString('hex');
        } else if (data) {
            errMsg = Buffer.from(data, 'base64').toString('utf-8');
        }
        return `error: ${step}(${txCommit.check_tx.code}) - ${log} (${errMsg})`;
    }
    return null;
}

export function panicEvmCallError(err: any, web3: Web3) {
    const ret = parseEvmCallError(err, web3);
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

export function sleep(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}



export class WrappedContract {
    [key: string]: any;
    private functionStateMutability: Map<string, string>;
    private functionOutputs: Map<string, any[]>;

    constructor(readonly web3: Web3, readonly address: string, methods: any, abi: any[]) {
        this.functionStateMutability = new Map();
        this.functionOutputs = new Map();

        // Parse ABI to get function stateMutability and outputs
        for (const item of abi) {
            if (item.type === 'function') {
                this.functionStateMutability.set(item.name, item.stateMutability || 'nonpayable');
                this.functionOutputs.set(item.name, item.outputs || []);
            }
        }

        // Get all method names (filter out duplicates like '0x...' and 'method(type)')
        const methodNames = Object.getOwnPropertyNames(methods)
            .filter(name => typeof methods[name] === 'function')
            .filter(name => !name.includes('(') && !name.startsWith('0x'));

        // Dynamically create wrapper methods that auto-call or auto-send based on stateMutability
        for (const methodName of methodNames) {
            const stateMutability = this.functionStateMutability.get(methodName) || 'nonpayable';
            const isReadOnly = stateMutability === 'view' || stateMutability === 'pure';
            const outputs = this.functionOutputs.get(methodName) || [];

            this[methodName] = async (...args: any[]) => {
                const originalMethod = methods[methodName](...args);

                // Automatically choose call() or send() based on stateMutability
                if (isReadOnly) {
                    const resp = await originalMethod.call();

                    // Decode response data using ABI
                    if (resp.value && !resp.value.vmErr && resp.value.returnData) {
                        return this.decodeOutputs(resp.value.returnData, outputs);
                    }
                    return resp;
                } else {
                    return await originalMethod.send({from: web3.beatoz.accounts.wallet.get(0)!.address, gas: 20000000});
                }
            };
        }
    }

    private decodeOutputs(returnData: string, outputs: any[]): any {
        if (outputs.length === 0) {
            return undefined;
        }

        if (outputs.length === 1) {
            // Single output - decode and return directly
            return this.web3.beatoz.abi.decodeParameter(outputs[0].type, returnData);
        }

        // Multiple outputs - decode as parameters and return as array
        const decoded = this.web3.beatoz.abi.decodeParameters(outputs, returnData);

        // Return as array
        return Object.values(decoded).slice(0, outputs.length);
    }
}