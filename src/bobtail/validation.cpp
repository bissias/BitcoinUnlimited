// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bobtail/validation.h"

#include "blockrelay/blockrelay_common.h"
#include "blockstorage/blockstorage.h"
#include "blockstorage/sequential_files.h"
#include "bobtail/bobtail.h"
#include "bobtail/bobtailblock.h"
#include "bobtail/dag.h"
#include "checkpoints.h"
#include "connmgr.h"
#include "consensus/merkle.h"
#include "consensus/tx_verify.h"
#include "dosman.h"
#include "expedited.h"
#include "index/txindex.h"
#include "init.h"
#include "requestManager.h"
#include "sync.h"
#include "timedata.h"
#include "txadmission.h"
#include "txorphanpool.h"
#include "ui_interface.h"
#include "validation/validation.h"
#include "validationinterface.h"

#include <boost/scope_exit.hpp>
#include <unordered_set>

extern CBobtailDagSet bobtailDagSet;
extern bool fCheckForPruning;
extern std::map<uint256, NodeId> mapBlockSource;

extern bool AbortNode(CValidationState &state, const std::string &strMessage, const std::string &userMessage = "");

static int64_t nTimeCheck = 0;
static int64_t nTimeForks = 0;
// static int64_t nTimeVerify = 0;
// static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeCallbacks = 0;
// static int64_t nTimeTotal = 0;
// static int64_t nTimeReadFromDisk = 0;
// static int64_t nTimeConnectTotal = 0;
// static int64_t nTimeFlush = 0;
// static int64_t nTimeChainState = 0;
// static int64_t nTimePostConnect = 0;

//////////////////////////////////////////////////////////////////
//
// Header
//

bool CheckSubBlockHeader(const CBlockHeader &block, CValidationState &state, bool fCheckPOW)
{
    if (fCheckPOW && !CheckSubBlockPoW(block, Params().GetConsensus(), BOBTAIL_K))
    {
        return state.DoS(50, error("CheckSubBlockHeader(): subblock proof of work failed"), REJECT_INVALID, "high-hash");
    }

    // Check timestamp
    if (block.GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
        return state.Invalid(
            error("CheckSubBlockHeader(): block timestamp too far in the future"), REJECT_INVALID, "time-too-new");

    return true;
}

bool AcceptSubBlockBlockHeader(const CBlockHeader &block,
    CValidationState &state,
    const CChainParams &chainparams,
    CBlockIndex **ppindex)
{
    AssertLockHeld(cs_main);
    // Check for duplicate
    uint256 hash = block.GetHash();
    CBlockIndex *pindex = nullptr;
    if (hash != chainparams.GetConsensus().hashGenesisBlock)
    {
        pindex = LookupBlockIndex(hash);
        if (pindex)
        {
            // Block header is already known.
            if (ppindex)
                *ppindex = pindex;
            {
                READLOCK(cs_mapBlockIndex);
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return state.Invalid(
                        error("%s: subblock %s height %d is marked invalid", __func__, hash.ToString(), pindex->nHeight),
                        0, "duplicate");
            }
            return true;
        }

        if (!CheckSubBlockHeader(block, state))
            return false;

        // Get prev block index
        CBlockIndex *pindexPrev = LookupBlockIndex(block.hashPrevBlock);
        if (!pindexPrev)
            return state.DoS(10, error("%s: previous block %s not found while accepting %s", __func__,
                                     block.hashPrevBlock.ToString(), hash.ToString()),
                0, "bad-prevblk");
        {
            READLOCK(cs_mapBlockIndex);
            if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
                return state.DoS(100,
                    error("%s: previous block %s is invalid", __func__, pindexPrev->GetBlockHash().GetHex().c_str()),
                    REJECT_INVALID, "bad-prevblk");
        }

        // If the parent block belongs to the set of checkpointed blocks but it has a mismatched hash,
        // then we are on the wrong fork so ignore
        if (fCheckpointsEnabled && !CheckAgainstCheckpoint(pindexPrev->nHeight, *pindexPrev->phashBlock, chainparams))
            return error("%s: CheckAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());

        if (!ContextualCheckBlockHeader(block, state, pindexPrev))
            return false;
    }
    if (pindex == nullptr)
        pindex = AddToBlockIndex(block);

    if (ppindex)
        *ppindex = pindex;

    return true;
}

bool CheckBobtailBlockHeader(const CBlockHeader &block, CValidationState &state)
{
    // fCheckPOW kept only for legacy compatibility
    if (true) //TODO: add Bobtail header validty check here
    {
        return state.DoS(50, error("CheckBobtailBlockHeader(): bobtail block validity check failed"), REJECT_INVALID, "high-hash");
    }

    // Check timestamp
    if (block.GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
        return state.Invalid(
            error("CheckBobtailBlockHeader(): block timestamp too far in the future"), REJECT_INVALID, "time-too-new");

    return true;
}

bool AcceptBobtailBlockBlockHeader(const CBlockHeader &block,
    CValidationState &state,
    const CChainParams &chainparams,
    CBlockIndex **ppindex)
{
    AssertLockHeld(cs_main);
    // Check for duplicate
    uint256 hash = block.GetHash();
    CBlockIndex *pindex = nullptr;
    if (hash != chainparams.GetConsensus().hashGenesisBlock)
    {
        pindex = LookupBlockIndex(hash);
        if (pindex)
        {
            // Block header is already known.
            if (ppindex)
                *ppindex = pindex;
            {
                READLOCK(cs_mapBlockIndex);
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return state.Invalid(
                        error("%s: subblock %s height %d is marked invalid", __func__, hash.ToString(), pindex->nHeight),
                        0, "duplicate");
            }
            return true;
        }

        if (!CheckBobtailBlockHeader(block, state))
            return false;

        // Get prev block index
        CBlockIndex *pindexPrev = LookupBlockIndex(block.hashPrevBlock);
        if (!pindexPrev)
            return state.DoS(10, error("%s: previous block %s not found while accepting %s", __func__,
                                     block.hashPrevBlock.ToString(), hash.ToString()),
                0, "bad-prevblk");
        {
            READLOCK(cs_mapBlockIndex);
            if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
                return state.DoS(100,
                    error("%s: previous block %s is invalid", __func__, pindexPrev->GetBlockHash().GetHex().c_str()),
                    REJECT_INVALID, "bad-prevblk");
        }

        // If the parent block belongs to the set of checkpointed blocks but it has a mismatched hash,
        // then we are on the wrong fork so ignore
        if (fCheckpointsEnabled && !CheckAgainstCheckpoint(pindexPrev->nHeight, *pindexPrev->phashBlock, chainparams))
            return error("%s: CheckAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());

        if (!ContextualCheckBlockHeader(block, state, pindexPrev))
            return false;
    }
    if (pindex == nullptr)
        pindex = AddToBlockIndex(block);

    if (ppindex)
        *ppindex = pindex;

    return true;
}


//////////////////////////////////////////////////////////////////
//
// Block/chain
//

bool CheckSubBlock(const CSubBlock &block, CValidationState &state, bool fCheckPOW, bool fCheckMerkleRoot)
{
    // These are checks that are independent of context.

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, fCheckPOW))
        return false;

    // Check the merkle root.
    if (fCheckMerkleRoot)
    {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(
                100, error("CheckSubBlock(): hashMerkleRoot mismatch"), REJECT_INVALID, "bad-txnmrklroot", true);

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(
                100, error("CheckSubBlock(): duplicate transaction"), REJECT_INVALID, "bad-txns-duplicate", true);
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.

    // Size limits
    if (block.vtx.empty())
    {
        return state.DoS(100, error("CheckSubBlock(): size limits failed"), REJECT_INVALID, "bad-blk-length");
    }

    // First transaction must be proofbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsProofBase())
    {
        return state.DoS(100, error("CheckSubBlock(): first tx is not proofbase"), REJECT_INVALID, "bad-pb-missing");
    }

    for (unsigned int i = 1; i < block.vtx.size(); i++)
    {
        if (block.vtx[i]->IsProofBase())
        {
            return state.DoS(100, error("CheckSubBlock(): more than one proofbase"), REJECT_INVALID, "bad-pb-multiple");
        }
    }

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        if (block.vtx[i]->IsCoinBase())
        {
            return state.DoS(100, error("CheckSubBlock(): subblock contains a coinbase"), REJECT_INVALID, "bad-cb-contains");
        }
    }

    // Check transactions
    for (const auto &tx : block.vtx)
    {
        if (!CheckTransaction(tx, state))
        {
            return error("CheckSubBlock(): CheckTransaction of %s failed with %s", tx->GetHash().ToString(),
                FormatStateMessage(state));
        }
    }
    return true;
}

bool TestSubBlockValidity(CValidationState &state,
    const CChainParams &chainparams,
    const CSubBlock &block,
    CBlockIndex *pindexPrev,
    bool fCheckPOW,
    bool fCheckMerkleRoot,
    bool fConservative)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev && pindexPrev == chainActive.Tip());
    // Ensure that if there is a checkpoint on this height, that this block is the one.
    if (fCheckpointsEnabled && !CheckAgainstCheckpoint(pindexPrev->nHeight + 1, block.GetHash(), chainparams))
        return error("%s: CheckAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());

    CCoinsViewCache viewNew(pcoinsTip);
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;

    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, pindexPrev))
        return false;
    if (!CheckSubBlock(block, state, fCheckPOW, fCheckMerkleRoot))
        return false;
    if (!ContextualCheckBlock(block, state, pindexPrev, fConservative))
        return false;
    assert(state.IsValid());

    return true;
}

bool CheckBobtailBlock(const CBobtailBlock &block, CValidationState &state, bool fCheckPOW, bool fCheckMerkleRoot)
{
    if (fCheckPOW && !CheckBobtailPoW(block, Params().GetConsensus(), BOBTAIL_K))
    {
        return state.DoS(50, error("CheckBobtailBlock(): bobtail proof of work failed"), REJECT_INVALID, "high-hash");
    }

    // Check timestamp
    if (block.GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
        return state.Invalid(
            error("CheckBobtailBlock(): block timestamp too far in the future"), REJECT_INVALID, "time-too-new");

    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, fCheckPOW))
        return false;

    // Check the merkle root.
    if (fCheckMerkleRoot)
    {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(
                100, error("CheckBlock(): hashMerkleRoot mismatch"), REJECT_INVALID, "bad-txnmrklroot", true);

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(
                100, error("CheckBlock(): duplicate transaction"), REJECT_INVALID, "bad-txns-duplicate", true);
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.

    // Size limits
    if (block.vtx.empty())
        return state.DoS(100, error("CheckBlock(): size limits failed"), REJECT_INVALID, "bad-blk-length");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.DoS(100, error("CheckBlock(): first tx is not coinbase"), REJECT_INVALID, "bad-cb-missing");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.DoS(100, error("CheckBlock(): more than one coinbase"), REJECT_INVALID, "bad-cb-multiple");

    // Check transactions
    for (const auto &tx : block.vtx)
        if (!CheckTransaction(tx, state))
            return error("CheckBlock(): CheckTransaction of %s failed with %s", tx->GetHash().ToString(),
                FormatStateMessage(state));

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;
    return true;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
bool AcceptBobtailBlock(const CBobtailBlock &block,
    CValidationState &state,
    const CChainParams &chainparams,
    CBlockIndex **ppindex,
    bool fRequested,
    CDiskBlockPos *dbp)
{
    AssertLockHeld(cs_main);

    CBlockIndex *&pindex = *ppindex;

    // TODO: Actually should check BobtailHeader
    if (!AcceptBlockHeader(block, state, chainparams, &pindex))
    {
        return false;
    }

    LOG(PARALLEL, "Check BobtailBlock %s with chain work %s block height %d\n", pindex->phashBlock->ToString(),
        pindex->nChainWork.ToString(), pindex->nHeight);

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = false;
    {
        READLOCK(cs_mapBlockIndex);
        fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    }
    bool fHasMoreWork = (chainActive.Tip() ? pindex->nChainWork > chainActive.Tip()->nChainWork : true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead = (pindex->nHeight > int(chainActive.Height() + MIN_BLOCKS_TO_KEEP));

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave)
    {
        return true;
    }
    // If we didn't ask for it:
    if (!fRequested)
    {
        if (pindex->nTx != 0)
            return true; // This is a previously-processed block that was pruned
        if (!fHasMoreWork)
            return true; // Don't process less-work chains
        if (fTooFarAhead)
            return true; // Block height is too high
    }
    if ((!CheckBobtailBlock(block, state)) || !ContextualCheckBlock(block, state, pindex->pprev))
    {
        if (state.IsInvalid() && !state.CorruptionPossible())
        {
            {
                WRITELOCK(cs_mapBlockIndex);
                pindex->nStatus |= BLOCK_FAILED_VALID;
                setDirtyBlockIndex.insert(pindex);
            }
            // Now mark every block index on every chain that contains pindex as child of invalid
            MarkAllContainingChainsInvalid(pindex);
        }
        return false;
    }
    int nHeight = pindex->nHeight;
    // Write block to history file
    try
    {
        //TODO: Add serialization to CBobtailBlock so that (CBlock)block is not necessary
        unsigned int nBlockSize = ::GetSerializeSize((CBlock)block, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        if (dbp != nullptr)
        {
            blockPos = *dbp;
        }
        if (!FindBlockPos(state, blockPos, nBlockSize + 8, nHeight, block.GetBlockTime(), dbp != nullptr))
        {
            return error("AcceptBlock(): FindBlockPos failed");
        }
        if (dbp == nullptr)
        {
            if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
            {
                AbortNode(state, "Failed to write block");
            }
        }
        if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
        {
            return error("AcceptBlock(): ReceivedBlockTransactions failed");
        }
    }
    catch (const std::runtime_error &e)
    {
        return AbortNode(state, std::string("System error: ") + e.what());
    }
    if (fCheckForPruning)
    {
        FlushStateToDisk(state, FLUSH_STATE_NONE); // we just allocated more disk space for block files
    }
    return true;
}

bool ConnectBobtailBlockPrevalidations(const CBobtailBlock &block,
    CValidationState &state,
    CBlockIndex *pindex,
    CCoinsViewCache &view,
    const CChainParams &chainparams,
    bool fJustCheck)
{
    int64_t nTimeStart = GetStopwatchMicros();

    // Check it again in case a previous version let a bad block in
    if (!CheckBobtailBlock(block, state, !fJustCheck, !fJustCheck))
    {
        return false;
    }

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == nullptr ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    int64_t nTime1 = GetStopwatchMicros();
    nTimeCheck += nTime1 - nTimeStart;
    LOG(BENCH, "    - Sanity checks: %.2fms [%.2fs]\n", 0.001 * (nTime1 - nTimeStart), nTimeCheck * 0.000001);

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    bool fEnforceBIP30 = (!pindex->phashBlock) || // Enforce on CreateNewBlock invocations which don't have a hash.
                         !((pindex->nHeight == 91842 &&
                               pindex->GetBlockHash() ==
                                   uint256S("0x00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")) ||
                             (pindex->nHeight == 91880 &&
                                 pindex->GetBlockHash() ==
                                     uint256S("0x00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")));

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried its no longer possible to create
    // further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for
    // the BIP30 check.
    if (pindex->pprev) // If this isn't the genesis block
    {
        CBlockIndex *pindexBIP34height = pindex->pprev->GetAncestor(chainparams.GetConsensus().BIP34Height);
        // Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't
        // correspond.
        fEnforceBIP30 =
            fEnforceBIP30 &&
            (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == chainparams.GetConsensus().BIP34Hash));

        if (fEnforceBIP30)
        {
            for (const auto &tx : block.vtx)
            {
                for (size_t o = 0; o < tx->vout.size(); o++)
                {
                    if (view.HaveCoin(COutPoint(tx->GetHash(), o)))
                    {
                        return state.DoS(100, error("ConnectBlock(): tried to overwrite transaction"), REJECT_INVALID,
                            "bad-txns-BIP30");
                    }
                }
            }
        }
    }

    int64_t nTime2 = GetStopwatchMicros();
    nTimeForks += nTime2 - nTime1;
    LOG(BENCH, "    - Fork checks: %.2fms [%.2fs]\n", 0.001 * (nTime2 - nTime1), nTimeForks * 0.000001);

    return true;
}

bool ConnectBobtailBlock(const CBobtailBlock &block,
    CValidationState &state,
    CBlockIndex *pindex,
    CCoinsViewCache &view,
    const CChainParams &chainparams,
    bool fJustCheck,
    bool fParallel)
{
    // pindex should be the header structure for this new block.  Check this by making sure that the nonces are the
    // same.
    assert(pindex->nNonce == block.nNonce);

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block.GetHash() == chainparams.GetConsensus().hashGenesisBlock)
    {
        if (!fJustCheck)
        {
            view.SetBestBlock(pindex->GetBlockHash());
        }
        return true;
    }

    /** BU: Start Section to validate inputs - if there are parallel blocks being checked
     *      then the winner of this race will get to update the UTXO.
     */
    AssertLockHeld(cs_main);
    // Section for boost scoped lock on the scriptcheck_mutex
    boost::thread::id this_id(boost::this_thread::get_id());

    if (!ConnectBobtailBlockPrevalidations(block, state, pindex, view, chainparams, fJustCheck))
        return false;

    const arith_uint256 nStartingChainWork = chainActive.Tip()->nChainWork;

    const int64_t timeBarrier = GetTime() - (24 * 3600 * checkScriptDays.Value());
    // Blocks that have various days of POW behind them makes them secure in that
    // real online nodes have checked the scripts.  Therefore, during initial block
    // download we don't need to check most of those scripts except for the most
    // recent ones.
    bool fScriptChecks = true;
    CBlockIndex *pBestHeader = pindexBestHeader.load();
    if (pBestHeader)
    {
        if (fReindex || fImporting)
            fScriptChecks = !fCheckpointsEnabled || block.nTime > timeBarrier;
        else
            fScriptChecks = !fCheckpointsEnabled || block.nTime > timeBarrier ||
                            (uint32_t)pindex->nHeight > pBestHeader->nHeight - (144 * checkScriptDays.Value());
    }

    CAmount nFees = 0;
    CBlockUndo blockundo;
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());

    // Discover how to handle this block
    bool canonical = fCanonicalTxsOrder;
    // Always allow overwite of fCanonicalTxsOrder but for regtest on BCH
    if (IsNov2018Activated(chainparams.GetConsensus(), chainActive.Tip()))
    {
        if (!(chainparams.NetworkIDString() == "regtest"))
        {
            canonical = true;
        }
    }
    else
    {
        if (!(chainparams.NetworkIDString() == "regtest"))
        {
            canonical = false;
        }
    }

    if (canonical)
    {
        if (!ConnectBlockCanonicalOrdering(
                block, state, pindex, view, chainparams, fJustCheck, fParallel, fScriptChecks, nFees, blockundo, vPos))
            return false;
    }
    else
    {
        if (!ConnectBlockDependencyOrdering(
                block, state, pindex, view, chainparams, fJustCheck, fParallel, fScriptChecks, nFees, blockundo, vPos))
            return false;
    }

    CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight, chainparams.GetConsensus());
    if (block.vtx[0]->GetValueOut() > blockReward)
        return state.DoS(100, error("ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)",
                                  block.vtx[0]->GetValueOut(), blockReward),
            REJECT_INVALID, "bad-cb-amount");

    if (fJustCheck)
        return true;

    int64_t nTime4 = GetStopwatchMicros();

    /*****************************************************************************************************************
     *                         Start update of UTXO, if this block wins the validation race *
     *****************************************************************************************************************/
    // If in PV mode and we win the race then we lock everyone out by taking cs_main but before updating the UTXO
    // and
    // terminating any competing threads.

    // Last check for chain work just in case the thread manages to get here before being terminated.
    if (PV->ChainWorkHasChanged(nStartingChainWork) || PV->QuitReceived(this_id, fParallel))
    {
        return false; // no need to lock cs_main before returning as it should already be locked.
    }

    // Quit any competing threads may be validating which have the same previous block before updating the UTXO.
    PV->QuitCompetingThreads(block.GetBlockHeader().hashPrevBlock);

    // Write undo information to disk
    {
        if (pindex->GetUndoPos().IsNull() || !pindex->IsValid(BLOCK_VALID_SCRIPTS))
        {
            if (pindex->GetUndoPos().IsNull())
            {
                CDiskBlockPos _pos;
                if (!FindUndoPos(
                        state, pindex->nFile, _pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
                    return error("ConnectBlock(): FindUndoPos failed");

                if (!WriteUndoToDisk(blockundo, _pos, pindex->pprev, chainparams.MessageStart()))
                    return AbortNode(state, "Failed to write undo data");

                // update nUndoPos in block index
                //
                // We must take the cs_mapBlockIndex after FindUndoPos() in order to maintain
                // the proper locking order of cs_main -> cs_LastBlockFile -> cs_mapBlockIndex
                WRITELOCK(cs_mapBlockIndex);
                pindex->nUndoPos = _pos.nPos;
                pindex->nStatus |= BLOCK_HAVE_UNDO;
            }

            WRITELOCK(cs_mapBlockIndex);
            pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
            setDirtyBlockIndex.insert(pindex);
        }
    }

    // Write transaction data to the txindex
    if (fTxIndex)
    {
        g_txindex->BlockConnected(block, pindex);
    }

    // add this block to the view's block chain (the main UTXO in memory cache)
    view.SetBestBlock(pindex->GetBlockHash());

    int64_t nTime5 = GetStopwatchMicros();
    nTimeIndex += nTime5 - nTime4;
    LOG(BENCH, "    - Index writing: %.2fms [%.2fs]\n", 0.001 * (nTime5 - nTime4), nTimeIndex * 0.000001);

    // Watch for changes to the previous coinbase transaction.
    static uint256 hashPrevBestCoinBase;
    GetMainSignals().UpdatedTransaction(hashPrevBestCoinBase);
    hashPrevBestCoinBase = block.vtx[0]->GetHash();

    int64_t nTime6 = GetStopwatchMicros();
    nTimeCallbacks += nTime6 - nTime5;
    LOG(BENCH, "    - Callbacks: %.2fms [%.2fs]\n", 0.001 * (nTime6 - nTime5), nTimeCallbacks * 0.000001);

    PV->Cleanup(block, pindex); // NOTE: this must be run whether in fParallel or not!

    // Track all recent txns in a block so we don't re-request them again. This can happen a txn announcement
    // arrives just after the block is received.
    for (const CTransactionRef &ptx : block.vtx)
    {
        txRecentlyInBlock.insert(ptx->GetHash());
    }

    return true;
}

bool ProcessNewBobtailBlock(CValidationState &state,
    const CChainParams &chainparams,
    CNode *pfrom,
    CBobtailBlock *pblock,
    bool fForceProcessing,
    CDiskBlockPos *dbp,
    bool fParallel)
{
    int64_t start = GetStopwatchMicros();
    LOG(THIN, "Processing new block %s from peer %s.\n", pblock->GetHash().ToString(),
        pfrom ? pfrom->GetLogName() : "myself");
    // if (IsChainNearlySyncd() && !fImporting && !fReindex)
    //    SendExpeditedBlock(*pblock, pfrom);

    bool checked = CheckBobtailBlock(*pblock, state);
    if (!checked)
    {
        LOGA("Invalid bobtail block: ver:%x time:%d Tx size:%d len:%d\n", pblock->nVersion, pblock->nTime,
            pblock->vtx.size(), pblock->GetBlockSize());
    }

    // WARNING: cs_main is not locked here throughout but is released and then re-locked during ActivateBestChain
    //          If you lock cs_main throughout ProcessNewBlock then you will in effect prevent PV from happening.
    //          TODO: in order to lock cs_main all the way through we must remove the locking from ActivateBestChain
    //                but it will require great care because ActivateBestChain requires cs_main however it is also
    //                called from other places.  Currently it seems best to leave cs_main here as is.
    {
        LOCK(cs_main);
        uint256 hash = pblock->GetHash();
        bool fRequested = requester.MarkBlockAsReceived(hash, pfrom);
        fRequested |= fForceProcessing;
        if (!checked)
        {
            return error("%s: CheckBobtailBlock FAILED", __func__);
        }

        // Store to disk
        CBlockIndex *pindex = nullptr;
        bool ret = AcceptBlock(*pblock, state, chainparams, &pindex, fRequested, dbp);
        if (pindex && pfrom)
        {
            const uint256 blockhash = pindex->GetBlockHash();
            mapBlockSource[blockhash] = pfrom->GetId();
        }
        CheckBlockIndex(chainparams.GetConsensus());

        CInv inv(MSG_BLOCK, hash);
        if (!ret)
        {
            // BU TODO: if block comes out of order (before its parent) this will happen.  We should cache the block
            // until the parents arrive.

            // If the block was not accepted then reset the fProcessing flag to false.
            requester.BlockRejected(inv, pfrom);

            return error("%s: AcceptBlock FAILED", __func__);
        }
        else
        {
            // We must indicate to the request manager that the block was received only after it has
            // been stored to disk (or been shown to be invalid). Doing so prevents unnecessary re-requests.
            requester.Received(inv, pfrom);
        }
    }
    /*! FIXME: There is somewhat of a race here during regtesting: If
      a lot of blocks are generated in one RPC call, parallel
      validation will make the registration order arbitrary which
      means delta blocks transmission and refering might sporadically
      fail. */
    //TODO: IS THIS NECESSARY?
    //CDeltaBlock::newStrong(pblock->GetHash());

    if (!ActivateBestChain(state, chainparams, pblock, fParallel))
    {
        if (state.IsInvalid() || state.IsError())
            return error("%s: ActivateBestChain failed", __func__);
        else
            return false;
    }

    int64_t end = GetStopwatchMicros();
    if (Logging::LogAcceptCategory(BENCH))
    {
        uint64_t maxTxSizeLocal = 0;
        uint64_t maxVin = 0;
        uint64_t maxVout = 0;
        CTransaction txIn;
        CTransaction txOut;
        CTransaction txLen;

        for (const auto &txref : pblock->vtx)
        {
            if (txref->vin.size() > maxVin)
            {
                maxVin = txref->vin.size();
                txIn = *txref;
            }
            if (txref->vout.size() > maxVout)
            {
                maxVout = txref->vout.size();
                txOut = *txref;
            }
            uint64_t len = ::GetSerializeSize(*txref, SER_NETWORK, PROTOCOL_VERSION);
            if (len > maxTxSizeLocal)
            {
                maxTxSizeLocal = len;
                txLen = *txref;
            }
        }

        LOG(BENCH,
            "ProcessNewBobtailBlock, time: %d, block: %s, len: %d, numTx: %d, maxVin: %llu, maxVout: %llu, maxTx:%llu\n",
            end - start, pblock->GetHash().ToString(), pblock->GetBlockSize(), pblock->vtx.size(), maxVin,
            maxVout, maxTxSizeLocal);
        LOG(BENCH, "tx: %s, vin: %llu, vout: %llu, len: %d\n", txIn.GetHash().ToString(), txIn.vin.size(),
            txIn.vout.size(), ::GetSerializeSize(txIn, SER_NETWORK, PROTOCOL_VERSION));
        LOG(BENCH, "tx: %s, vin: %llu, vout: %llu, len: %d\n", txOut.GetHash().ToString(), txOut.vin.size(),
            txOut.vout.size(), ::GetSerializeSize(txOut, SER_NETWORK, PROTOCOL_VERSION));
        LOG(BENCH, "tx: %s, vin: %llu, vout: %llu, len: %d\n", txLen.GetHash().ToString(), txLen.vin.size(),
            txLen.vout.size(), ::GetSerializeSize(txLen, SER_NETWORK, PROTOCOL_VERSION));
    }

    LOCK(cs_blockvalidationtime);
    nBlockValidationTime << (end - start);
    return true;
}
