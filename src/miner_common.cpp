// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "miner_common.h"
#include "pow.h"
#include "timedata.h"
#include "unlimited.h"
#include "validation/forks.h"

extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_coinbaseFlags;

void IncrementExtraNonce(CBlock *pblock, unsigned int &nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pblock->GetHeight(); // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);

    CScript script = (CScript() << nHeight << CScriptNum(nExtraNonce));
    CScript cbFlags;
    {
        LOCK(cs_coinbaseFlags);
        cbFlags = COINBASE_FLAGS;
    }
    if (script.size() + cbFlags.size() > MAX_COINBASE_SCRIPTSIG_SIZE)
    {
        cbFlags.resize(MAX_COINBASE_SCRIPTSIG_SIZE - script.size());
    }
    txCoinbase.vin[0].scriptSig = script + cbFlags;
    assert(txCoinbase.vin[0].scriptSig.size() <= MAX_COINBASE_SCRIPTSIG_SIZE);

    // On BCH if Nov15th 2018 has been activated make sure the coinbase is big enough
    uint64_t nCoinbaseSize = ::GetSerializeSize(txCoinbase, SER_NETWORK, PROTOCOL_VERSION);
    if (nCoinbaseSize < MIN_TX_SIZE && IsNov2018Activated(Params().GetConsensus(), chainActive.Tip()))
    {
        txCoinbase.vin[0].scriptSig << std::vector<uint8_t>(MIN_TX_SIZE - nCoinbaseSize - 1);
    }
    pblock->vtx[0] = (MakeTransactionRef(std::move(txCoinbase)));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}

void IncrementExtraNonce(CSubBlock *pblock, unsigned int &nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    // height not required for subblocks
    CMutableTransaction txCoinbase(*pblock->vtx[0]);

    CScript script = (CScript() << CScriptNum(nExtraNonce));
    CScript cbFlags;
    {
        LOCK(cs_coinbaseFlags);
        cbFlags = COINBASE_FLAGS;
    }
    if (script.size() + cbFlags.size() > MAX_COINBASE_SCRIPTSIG_SIZE)
    {
        cbFlags.resize(MAX_COINBASE_SCRIPTSIG_SIZE - script.size());
    }
    txCoinbase.vin[0].scriptSig = script + cbFlags;
    assert(txCoinbase.vin[0].scriptSig.size() <= MAX_COINBASE_SCRIPTSIG_SIZE);

    // On BCH if Nov15th 2018 has been activated make sure the coinbase is big enough
    uint64_t nCoinbaseSize = ::GetSerializeSize(txCoinbase, SER_NETWORK, PROTOCOL_VERSION);
    if (nCoinbaseSize < MIN_TX_SIZE && IsNov2018Activated(Params().GetConsensus(), chainActive.Tip()))
    {
        txCoinbase.vin[0].scriptSig << std::vector<uint8_t>(MIN_TX_SIZE - nCoinbaseSize - 1);
    }
    pblock->vtx[0] = (MakeTransactionRef(std::move(txCoinbase)));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}

int64_t UpdateTime(CBlockHeader *pblock, const Consensus::Params &consensusParams, const CBlockIndex *pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

    return nNewTime - nOldTime;
}
