import Web3 from '@beatoz/web3';
import * as fs from 'fs';
import path from 'path';
import { setTimeout } from 'timers/promises';
import {projectRoot, chainConfig, contractABI, parseTxCommitResult, panicTxCommitResult} from "./utils";

if (process.argv.length < 3) {
    console.log("Usage: ts-node deploy.ts [chainAlias]");
    process.exit(0);
}

const chainAlias = process.argv[2];
const chainCfg = chainConfig(chainAlias);
const web3 = new Web3(chainCfg.providerUrl);
web3.beatoz.accounts.wallet.add(chainCfg.deployerPrvKey);
const deployAcct = web3.beatoz.accounts.wallet.get(0)!;
console.log("chainId:", chainCfg.chainId, "deployer:", deployAcct.address);

main();

async function main() {
    // Execute deployment
    const verifierAddr = await deployContract("PlonkVerifier").catch(error => {
        console.error("PlonkVerifier deployment failed:", error);
        process.exit(1);
    });
    await deployContract("ZKToken", [verifierAddr]).catch(error => {
        console.error("ZKToken deployment failed:", error);
        process.exit(1);
    })
}


async function deployContract(dappAlias: string, params?: any[]) {
    params = params ?? [];
    const targetContractJson = contractABI(dappAlias);
    const targetContract = new web3.beatoz.Contract(targetContractJson.abi) as any;

    const retCommit = await targetContract.deploy(
        targetContractJson.bytecode,
        params,
        deployAcct,
        chainCfg.chainId,
        20000000).send();
    panicTxCommitResult(retCommit);

    await setTimeout(100);

    const contAddr = await web3.beatoz.contractAddrFromTx(retCommit.hash);
    console.log(contAddr, chainAlias);

    const save = {
        chainId: chainCfg.chainId,
        providerUrl: chainCfg.providerUrl,
        deployer: '0x' + deployAcct.address,
        name: dappAlias,
        contract: contAddr,
        height: retCommit.height,
        txHash: retCommit.hash
    }
    await fs.promises.writeFile(`${projectRoot()}/scripts/beatoz/deployed.${chainAlias}.${dappAlias}.json`, JSON.stringify(save, null, 2));
    return contAddr;
}