// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BOBTAIL_BOBTAILMINER_H
#define BITCOIN_BOBTAIL_BOBTAILMINER_H

#include "bobtail/bobtail.h"
#include "bobtail/dag.h"
#include "bobtail/subblock.h"
#include "miner_common.h"

#include <memory>
#include <stdint.h>

#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index_container.hpp"

class CBlockIndex;
class CChainParams;
class CReserveKey;
class CScript;
class CWallet;

extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_coinbaseFlags;

extern std::atomic<int64_t> nTotalPackage;
extern std::atomic<int64_t> nTotalScore;
extern CTweak<bool> miningCPFP;

namespace Consensus
{
struct Params;
};

struct CBobtailBlockTemplate
{
    CBobtailBlockRef bobtailblock;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;
    CBobtailBlockTemplate() : bobtailblock(new CBobtailBlock()) {}
};

class BobtailBlockAssembler
{
private:
    const CChainParams &chainparams;

    // Configuration parameters for the block size
    uint64_t nBlockMaxSize, nBlockMinSize;

    // Information on the current status of the block
    uint64_t nBlockSize;
    uint64_t nBlockTx;
    unsigned int nBlockSigOps;
    CAmount nFees;
    CTxMemPool::setEntries inBlock;

    // Chain context for the block
    int nHeight;
    int64_t nLockTimeCutoff;

    // Variables used for addScoreTxs and addPriorityTxs
    int lastFewTxs;
    bool blockFinished;

    bool may2020Enabled = false;
    uint64_t maxSigOpsAllowed = 0;

public:
    BobtailBlockAssembler(const CChainParams &chainparams);

    /** Internal method to construct a new block template */
    std::unique_ptr<CBobtailBlockTemplate> CreateNewBobtailBlock(const CScript &scriptPubKeyIn, int64_t coinbaseSize = -1);

private:
    // utility functions
    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock(const CScript &scriptPubKeyIn, int64_t coinbaseSize = -1);
    /** Add a tx to the block */
    void AddToBlock(std::vector<const CTxMemPoolEntry *> *vtxe, CTxMemPool::txiter iter);

    // incomplete, only used for delta blocks
    void AddToBlock(std::vector<const CTxMemPoolEntry *> *vtxe, CTxMemPoolEntry *entry);

    // Methods for how to add transactions to a block.
    /** Add transactions based on modified feerate */
    void addScoreTxs(std::vector<const CTxMemPoolEntry *> *vtxe);
    /** Add transactions based on tx "priority" */
    void addPriorityTxs(std::vector<const CTxMemPoolEntry *> *vtxe);

    /** Add transactions based on feerate including unconfirmed ancestors */
    void addPackageTxs(std::vector<const CTxMemPoolEntry *> *vtxe);

    // helper function for addScoreTxs and addPriorityTxs
    bool IsIncrementallyGood(uint64_t nExtraSize, unsigned int nExtraSigOps);
    /** Test if tx will still "fit" in the block */
    bool TestForBlock(CTxMemPool::txiter iter);
    /** Test if tx still has unconfirmed parents not yet in block */
    bool isStillDependent(CTxMemPool::txiter iter);

    /** Bytes to reserve for coinbase and block header */
    uint64_t reserveBlockSize(const CScript &scriptPubKeyIn, int64_t coinbaseSize = -1);
    /** Constructs a coinbase transaction */
    CTransactionRef coinbaseTx(const CScript &scriptPubKeyIn, int nHeight, CAmount nValue, const std::set<CDagNode> &dag);

    // helper functions for addPackageTxs()
    /** Test whether a package, if added to the block, would make the block exceed the sigops limits */
    bool TestPackageSigOps(uint64_t packageSize, unsigned int packageSigOps);
    /** Test if a set of transactions are all final */
    bool TestPackageFinality(const CTxMemPool::setEntries &package);
};

#endif
