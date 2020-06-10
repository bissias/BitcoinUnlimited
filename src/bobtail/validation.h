// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BOBTAIL_VALIDATION_H
#define BITCOIN_BOBTAIL_VALIDATION_H

#include "bobtail/bobtailblock.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "validation/forks.h"
#include "parallel.h"
#include "txdebugger.h"
#include "txmempool.h"
#include "versionbits.h"

/** Context-independent validity checks */
bool CheckSubBlockHeader(const CBlockHeader &block, CValidationState &state, bool fCheckPOW = true);

bool AcceptSubBlockBlockHeader(const CBlockHeader &block,
    CValidationState &state,
    const CChainParams &chainparams,
    CBlockIndex **ppindex = nullptr);

//TODO: This should accept a CBobtailBlockHeader once it is defined
bool CheckBobtailBlockHeader(const CBlockHeader &block, CValidationState &state);

//TODO: This should accept a CBobtailBlockHeader once it is defined
bool AcceptBobtailBlockBlockHeader(const CBlockHeader &block,
    CValidationState &state,
    const CChainParams &chainparams,
    CBlockIndex **ppindex = nullptr);

/** Check a block is completely valid from start to finish (only works on top of our current best block, with cs_main
 * held) */
bool TestSubBlockValidity(CValidationState &state,
    const CChainParams &chainparams,
    const CSubBlock &block,
    CBlockIndex *pindexPrev,
    bool fCheckPOW = true,
    bool fCheckMerkleRoot = true,
    bool fConservative = false);

bool CheckBobtailBlock(const CBobtailBlock &block, CValidationState &state, bool fCheckPOW = true, bool fCheckMerkleRoot = true);

/** Apply the effects of this block (with given index) on the UTXO set represented by coins */
bool ConnectBobtailBlock(const CBobtailBlock &block,
    CValidationState &state,
    CBlockIndex *pindex,
    CCoinsViewCache &view,
    const CChainParams &chainparams,
    bool fJustCheck = false,
    bool fParallel = false);

/**
 * Process an incoming block. This only returns after the best known valid
 * block is made active. Note that it does not, however, guarantee that the
 * specific block passed to it has been checked for validity!
 *
 * @param[out]  state   This may be set to an Error state if any error occurred processing it, including during
 * validation/connection/etc of otherwise unrelated blocks during reorganisation; or it may be set to an Invalid state
 * if pblock is itself invalid (but this is not guaranteed even when the block is checked). If you want to *possibly*
 * get feedback on whether pblock is valid, you must also install a CValidationInterface (see validationinterface.h) -
 * this will have its BlockChecked method called whenever *any* block completes validation.
 * @param[in]   pfrom   The node which we are receiving the block from; it is added to mapBlockSource and may be
 * penalised if the block is invalid.
 * @param[in]   pblock  The block we want to process.
 * @param[in]   fForceProcessing Process this block even if unrequested; used for non-network block sources and
 * whitelisted peers.
 * @param[out]  dbp     If pblock is stored to disk (or already there), this will be set to its location.
 * @return True if state.IsValid()
 */
bool ProcessNewBobtailBlock(CValidationState &state,
    const CChainParams &chainparams,
    CNode *pfrom,
    CBobtailBlock *pblock,
    bool fForceProcessing,
    CDiskBlockPos *dbp,
    bool fParallel);

#endif
