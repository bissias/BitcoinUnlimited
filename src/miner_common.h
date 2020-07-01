// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MINER_COMMON_H
#define BITCOIN_MINER_COMMON_H

#include "bobtail/subblock.h"
#include "chain.h"
#include "consensus/params.h"
#include "primitives/block.h"
#include "txmempool.h"

static const bool DEFAULT_PRINTPRIORITY = false;

struct NumericallyLessTxHashComparator
{
public:
    bool operator()(const CTxMemPoolEntry *a, const CTxMemPoolEntry *b) const
    {
        return a->GetTx().GetHash() < b->GetTx().GetHash();
    }
    bool operator()(const CTransactionRef &a, const CTransactionRef &b) const
    {
        return a->GetHash() < b->GetHash();
    }
};

class ScoreCompare
{
public:
    ScoreCompare() {}
    bool operator()(const CTxMemPool::txiter a, const CTxMemPool::txiter b) const
    {
        return CompareTxMemPoolEntryByScore()(*b, *a); // Convert to less than
    }
};

/** Modify the extranonce in a block */
void IncrementExtraNonce(CBlock *pblock, unsigned int &nExtraNonce);
void IncrementExtraNonce(CSubBlock *pblock, unsigned int &nExtraNonce);
int64_t UpdateTime(CBlockHeader *pblock, const Consensus::Params &consensusParams, const CBlockIndex *pindexPrev);

#endif
