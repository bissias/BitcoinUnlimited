// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "blockrelay/netdeltablocks.h"
#include "blockstorage/blockstorage.h"
#include "bobtail/bobtail.h"
#include "bobtail/dag.h"
#include "bobtail/bobtail_miner.h"
#include "bobtail/subblock_miner.h"
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
extern std::set<CBobtailBlock> bobtailBlocks;

UniValue generateBobtailBlocks(boost::shared_ptr<CReserveScript> coinbaseScript,
    int nSubGenerate=0,
    int nBobGenerate=0,
    uint64_t nMaxTries=0,
    bool keepScript=false)
{
    static const int nInnerLoopCount = 0x10000;

    unsigned int nExtraNonce = 0;
    UniValue blockHashes(UniValue::VARR);

    int numSubBlocks = 0;
    int numBobBlocks = 0;
    std::vector<CSubBlockRef> vdag;

    while (numSubBlocks < nSubGenerate || numBobBlocks < nBobGenerate)
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
               !CheckSubBlockPoW(*pblock, Params().GetConsensus(), BOBTAIL_K))
        {
            ++pblock->nNonce;
            --nMaxTries;
        }
        if (nMaxTries == 0)
            break;
        if (pblock->nNonce == nInnerLoopCount)
            continue;

        if (CheckSubBlockPoW(*pblock, Params().GetConsensus(), BOBTAIL_K))
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
            numSubBlocks++;

            // Add subblock to the dag
            vdag.push_back(pblocktemplate->subblock);

            // Assemble bobtail block
            std::unique_ptr<CBobtailBlockTemplate> pBobtailBlockTemplate;
            {
                TxAdmissionPause lock; // flush any tx waiting to enter the mempool
                pBobtailBlockTemplate = BobtailBlockAssembler(Params()).CreateNewBobtailBlock(coinbaseScript->reserveScript);
            }
            if (!pBobtailBlockTemplate.get())
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new bobtail block");
            CBobtailBlock *pBobtailBlock = pBobtailBlockTemplate->bobtailblock.get();
            pBobtailBlock->vdag = vdag;

            // Check if bobtail block meets strong PoW
            if (CheckBobtailPoW(*pBobtailBlock, Params().GetConsensus(), BOBTAIL_K))
            {
                PV->StopAllValidationThreads(pBobtailBlock->GetBlockHeader().nBits);

                CValidationState state;
                if (!ProcessNewBobtailBlock(state, Params(), nullptr, pBobtailBlock, true, nullptr, false))
                {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBobtailBlock, bobtail block not accepted");
                }

                // mark script as important because it was used at least for one coinbase output if the script came from the
                // wallet
                if (keepScript)
                {
                    coinbaseScript->KeepScript();
                }
                numBobBlocks++;

                if (nBobGenerate > 0)
                    blockHashes.push_back(pBobtailBlock->GetHash().GetHex());
            }
        }
        if (nSubGenerate > 0)
            blockHashes.push_back(pblock->GetHash().GetHex());
    }
    // we dont need to flush to disk because no blocks that can be written to disk were made
    // we dont update tip because no cblocks were mined, only csubblocks
    return blockHashes;
}

UniValue generatesubblocks(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error("generate numSubBlocks ( maxtries )\n"
                            "\nMine up to numSubBlocks subBlocks immediately (before the RPC call returns)\n"
                            "\nArguments:\n"
                            "1. numSubBlocks    (numeric, required) How many subBlocks are generated immediately.\n"
                            "2. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
                            "\nResult\n"
                            "[ blockhashes ]     (array) hashes of blocks generated\n"
                            "\nExamples:\n"
                            "\nGenerate 11 subBlocks\n" +
                            HelpExampleCli("generate", "11"));

    int nSubGenerate = params[0].get_int();
    uint64_t nMaxTries = 100000000;
    if (params.size() > 1)
    {
        nMaxTries = params[1].get_int();
    }

    boost::shared_ptr<CReserveScript> coinbaseScript;
    GetMainSignals().ScriptForMining(coinbaseScript);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbaseScript)
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    // throw an error if no script was provided
    if (coinbaseScript->reserveScript.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available (mining requires a wallet)");

    return generateBobtailBlocks(coinbaseScript, nSubGenerate, 0, nMaxTries, true);
}

UniValue generatebobtailblocks(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error("generate numBobtailBlocks ( maxtries )\n"
                            "\nMine up to numBobtailBlocks bobtailBlocks immediately (before the RPC call returns)\n"
                            "\nArguments:\n"
                            "1. numBobtailBlocks    (numeric, required) How many bobtailBlocks are generated immediately.\n"
                            "2. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
                            "\nResult\n"
                            "[ blockhashes ]     (array) hashes of blocks generated\n"
                            "\nExamples:\n"
                            "\nGenerate 11 bobtailBlocks\n" +
                            HelpExampleCli("generate", "11"));

    int nBobGenerate = params[0].get_int();
    uint64_t nMaxTries = 100000000;
    if (params.size() > 1)
    {
        nMaxTries = params[1].get_int();
    }

    boost::shared_ptr<CReserveScript> coinbaseScript;
    GetMainSignals().ScriptForMining(coinbaseScript);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbaseScript)
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    // throw an error if no script was provided
    if (coinbaseScript->reserveScript.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available (mining requires a wallet)");

    return generateBobtailBlocks(coinbaseScript, 0, nBobGenerate, nMaxTries, true);
}

UniValue generatesubblockstoaddress(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error("generatetoaddress numSubBlocks address (maxtries)\n"
                            "\nMine sub blocks immediately to a specified address (before the RPC call returns)\n"
                            "\nArguments:\n"
                            "1. numSubBlocks    (numeric, required) How many subBlocks are generated immediately.\n"
                            "2. address    (string, required) The address to send the newly generated bitcoin to.\n"
                            "3. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
                            "\nResult\n"
                            "[ blockhashes ]     (array) hashes of blocks generated\n"
                            "\nExamples:\n"
                            "\nGenerate 11 bobtailblocks to myaddress\n" +
                            HelpExampleCli("generatetoaddress", "11 \"myaddress\""));

    int nSubGenerate = params[0].get_int();
    uint64_t nMaxTries = 100000000;
    if (params.size() > 2)
    {
        nMaxTries = params[2].get_int();
    }

    CTxDestination destination = DecodeDestination(params[1].get_str());
    if (!IsValidDestination(destination))
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    boost::shared_ptr<CReserveScript> coinbaseScript(new CReserveScript());
    coinbaseScript->reserveScript = GetScriptForDestination(destination);

    return generateBobtailBlocks(coinbaseScript, nSubGenerate, 0, nMaxTries, false);
}

UniValue generatebobtailblockstoaddress(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error("generatetoaddress numBobtailBlocks address (maxtries)\n"
                            "\nMine bobtail blocks immediately to a specified address (before the RPC call returns)\n"
                            "\nArguments:\n"
                            "1. numBobtailBlocks    (numeric, required) How many subBlocks are generated immediately.\n"
                            "2. address    (string, required) The address to send the newly generated bitcoin to.\n"
                            "3. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
                            "\nResult\n"
                            "[ blockhashes ]     (array) hashes of blocks generated\n"
                            "\nExamples:\n"
                            "\nGenerate 11 bobtailblocks to myaddress\n" +
                            HelpExampleCli("generatetoaddress", "11 \"myaddress\""));

    int nBobGenerate = params[0].get_int();
    uint64_t nMaxTries = 100000000;
    if (params.size() > 2)
    {
        nMaxTries = params[2].get_int();
    }

    CTxDestination destination = DecodeDestination(params[1].get_str());
    if (!IsValidDestination(destination))
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    boost::shared_ptr<CReserveScript> coinbaseScript(new CReserveScript());
    coinbaseScript->reserveScript = GetScriptForDestination(destination);

    return generateBobtailBlocks(coinbaseScript, 0, nBobGenerate, nMaxTries, false);
}


UniValue getdaginfo(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw std::runtime_error(
            "getdaginfo\n"
            "Returns an object containing info about the current bobtail dag.\n"
            "\nResult:\n"
            "{\n"
            "  \"size\": xxxxx,           (numeric) the number of dag nodes in the dag\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getdaginfo", "") + HelpExampleRpc("getdaginfo", ""));
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("size", bobtailDagSet.Size());

    return obj;
}

UniValue getdagtips(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw std::runtime_error(
            "getdaginfo\n"
            "Returns an object containing info about the current bobtail dag.\n"
            "\nResult:\n"
            "{\n"
                "[ blockhashes ]     (array) hashes of the subblocks at the dag tips\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getdaginfo", "") + HelpExampleRpc("getdaginfo", ""));
    }

    UniValue obj(UniValue::VARR);
    std::vector<uint256> tip_hashes = bobtailDagSet.GetTips();
    for (auto &hash : tip_hashes)
    {
        obj.push_back(hash.GetHex());
    }
    return obj;
}

UniValue getbobtailinfo(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw std::runtime_error(
            "getbobtailinfo\n"
            "Returns an object containing info about the current bobtail blocks.\n"
            "\nResult:\n"
            "{\n"
                "chaintip: hash     (array) hash of bobtail block at tip of current chain\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getbobtailinfo", "") + HelpExampleRpc("getbobtailinfo", ""));
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chaintip", chainActive.Tip()->phashBlock->GetHex());
    return obj;
}


static const CRPCCommand commands[] = {
    //  category              name                      actor (function)         okSafeMode
    //  --------------------- ------------------------  -----------------------  ----------
    {"generating", "generatesubblocks", &generatesubblocks, true}, {"generating", "generatebobtailblocks", &generatebobtailblocks, true},
    {"generating", "generatesubblockstoaddress", &generatesubblockstoaddress, true}, {"generating", "generatesubblockstoaddress", &generatesubblockstoaddress, true},
    {"bobtail", "getdaginfo", &getdaginfo, true}, {"bobtail", "getdagtips", &getdagtips, true}, {"bobtail", "getbobtailinfo", &getbobtailinfo, true}
};

void RegisterBobtailRPCCommands(CRPCTable &table)
{
    for (auto cmd : commands)
        table.appendCommand(cmd);
}
