// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "blockrelay/netdeltablocks.h"
#include "blockstorage/blockstorage.h"
#include "bobtail/bobtail.h"
#include "bobtail/dag.h"
#include "bobtail/miner.h"
#include "bobtail/validation.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "dstencode.h"
#include "init.h"
#include "main.h"
#include "net.h"
#include "parallel.h"
#include "pow.h"
#include "rpc/server.h"
#include "txadmission.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validationinterface.h"

#include <cstdlib>
#include <stdint.h>

#include <boost/assign/list_of.hpp>
#include <boost/shared_ptr.hpp>

extern CBobtailDagSet bobtailDagSet;

UniValue generateBobtailBlocks(boost::shared_ptr<CReserveScript> coinbaseScript,
    int nGenerate,
    uint64_t nMaxTries,
    bool keepScript,
    int weak_mode)
{
    static const int nInnerLoopCount = 0x10000;

    unsigned int nExtraNonce = 0;
    UniValue blockHashes(UniValue::VARR);

    int numblocks = 0;

    while (numblocks < nGenerate)
    {
        std::unique_ptr<CSubBlockTemplate> pblocktemplate;
        {
            TxAdmissionPause lock; // flush any tx waiting to enter the mempool
            pblocktemplate = SubBlockAssembler(Params()).CreateNewSubBlock(coinbaseScript->reserveScript);
        }
        if (!pblocktemplate.get())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        LOG(WB, "Using delta block for RPC generate.\n");
        CSubBlock *pblock = pblocktemplate->subblock.get();
        {
            // LOCK(cs_main);
            IncrementExtraNonce(pblock, nExtraNonce);
        }

        // Generally look for weak PoW
        while (nMaxTries > 0 && pblock->nNonce < nInnerLoopCount &&
               !CheckProofOfWork(pblock->GetHash(), weakPOWfromPOW(pblock->nBits), Params().GetConsensus(), true))
        {
            ++pblock->nNonce;
            --nMaxTries;
        }
        if (nMaxTries == 0)
            break;
        if (pblock->nNonce == nInnerLoopCount)
            continue;

        // Now check if Bobtail PoW is also satisfied
        if (CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus()))
        {
            // In we are mining our own block or not running in parallel for any reason
            // we must terminate any block validation threads that are currently running,
            // Unless they have more work than our own block or are processing a chain
            // that has more work than our block.
            PV->StopAllValidationThreads(pblock->GetBlockHeader().nBits);

            if (!ProcessNewSubBlock(*pblock))
            {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewSubBlock, subblock not accepted");
            }

            // mark script as important because it was used at least for one coinbase output if the script came from the
            // wallet
            if (keepScript)
            {
                coinbaseScript->KeepScript();
            }
            numblocks++;
        }
        blockHashes.push_back(pblock->GetHash().GetHex());
    }
    // we dont need to flush to disk because no blocks that can be written to disk were made
    // we dont update tip because no cblocks were mined, only csubblocks
    return blockHashes;
}

UniValue generatebobtail(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error("generate numblocks ( maxtries )\n"
                            "\nMine up to numblocks bobtailblocks immediately (before the RPC call returns)\n"
                            "\nArguments:\n"
                            "1. numblocks    (numeric, required) How many blocks are generated immediately.\n"
                            "2. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
                            "3. weak_mode     (numeric, optional) Should weak blocks be generated?\n"
                            "                                    1 : only strong, 2: only weak, 3 : strong and weak\n"
                            "\nResult\n"
                            "[ blockhashes ]     (array) hashes of blocks generated\n"
                            "\nExamples:\n"
                            "\nGenerate 11 bobtailblocks\n" +
                            HelpExampleCli("generate", "11"));

    int nGenerate = params[0].get_int();
    uint64_t nMaxTries = 100000000;
    if (params.size() > 1)
    {
        nMaxTries = params[1].get_int();
    }
    int weak_mode = 1;
    if (params.size() > 2)
        weak_mode = params[2].get_int();

    boost::shared_ptr<CReserveScript> coinbaseScript;
    GetMainSignals().ScriptForMining(coinbaseScript);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbaseScript)
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    // throw an error if no script was provided
    if (coinbaseScript->reserveScript.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available (mining requires a wallet)");

    return generateBobtailBlocks(coinbaseScript, nGenerate, nMaxTries, true, weak_mode);
}

UniValue generatebobtailtoaddress(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error("generatetoaddress numblocks address (maxtries)\n"
                            "\nMine bobtailblocks immediately to a specified address (before the RPC call returns)\n"
                            "\nArguments:\n"
                            "1. numblocks    (numeric, required) How many blocks are generated immediately.\n"
                            "2. address    (string, required) The address to send the newly generated bitcoin to.\n"
                            "3. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
                            "4. weak_mode     (numeric, optional) Generate weak blocks?\n"
                            "\nResult\n"
                            "[ blockhashes ]     (array) hashes of blocks generated\n"
                            "\nExamples:\n"
                            "\nGenerate 11 bobtailblocks to myaddress\n" +
                            HelpExampleCli("generatetoaddress", "11 \"myaddress\""));

    int nGenerate = params[0].get_int();
    uint64_t nMaxTries = 100000000;
    if (params.size() > 2)
    {
        nMaxTries = params[2].get_int();
    }

    int weak_mode = 1;
    if (params.size() > 3)
        weak_mode = params[3].get_int();

    CTxDestination destination = DecodeDestination(params[1].get_str());
    if (!IsValidDestination(destination))
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    boost::shared_ptr<CReserveScript> coinbaseScript(new CReserveScript());
    coinbaseScript->reserveScript = GetScriptForDestination(destination);

    return generateBobtailBlocks(coinbaseScript, nGenerate, nMaxTries, false, weak_mode);
}

static const CRPCCommand commands[] = {
    //  category              name                      actor (function)         okSafeMode
    //  --------------------- ------------------------  -----------------------  ----------
    {"generating", "generatebobtail", &generatebobtail, true}, {"generating", "generatebobtailtoaddress", &generatebobtailtoaddress, true},
};

void RegisterBobtailRPCCommands(CRPCTable &table)
{
    for (auto cmd : commands)
        table.appendCommand(cmd);
}
