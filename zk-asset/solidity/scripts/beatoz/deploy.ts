import Web3 from '@beatoz/web3';
import * as fs from 'fs';
import path from 'path';
import { setTimeout } from 'timers/promises';
import {projectRoot, chainConfig, contractJson, panicTxCommitResult, panicEvmCallError, WrappedContract} from "./utils";
import {panicErrorCodeToMessage} from "hardhat/internal/hardhat-network/stack-traces/panic-errors";

// main();
//
// async function main() {
//     // Execute deployment
//     const verifier = await deploy(process.argv[2], "PlonkVerifier").catch(error => {
//         console.error("PlonkVerifier deployment failed:", error);
//         process.exit(1);
//     });
//     const zkToken = await deploy(process.argv[2],"ZKToken", [verifier.address]).catch(error => {
//         console.error("ZKToken deployment failed:", error);
//         process.exit(1);
//     })
//
//     console.log(`${verifier.address}`, "PlonkVerifier");
//     console.log(`${zkToken.address}`, "ZKToken");
// }


export async function deploy(chainAlias: string, dappAlias: string, params?: any[]) {
    const chainCfg = chainConfig(chainAlias);
    const web3 = new Web3(chainCfg.providerUrl);
    web3.beatoz.accounts.wallet.add(chainCfg.deployerPrvKey);
    const deployAcct = web3.beatoz.accounts.wallet.get(0)!;

    params = params ?? [];
    const targetContractJson = contractJson(dappAlias);
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

    // Set contract address before creating wrapped contract
    targetContract.options.address = contAddr;

    // Create wrapped contract with all methods
    return new WrappedContract(web3, contAddr, targetContract.methods, targetContractJson.abi);
}