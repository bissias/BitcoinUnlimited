// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BOBTAIL_BOBTAIL_H
#define BITCOIN_BOBTAIL_BOBTAIL_H

#include "arith_uint256.h"
#include "bobtailblock.h"
#include "consensus/params.h"
#include "subblock.h"

const double KOS_INCLUSION_PROB = 0.99999;
const int DEFAULT_SCALE_FACTOR = 1000;

bool IsSubBlockMalformed(const CSubBlock &subblock);
bool ProcessNewSubBlock(const CSubBlock &subblock);
bool CheckBobtailPoW(CBobtailBlock block, const Consensus::Params &params, uint8_t k);
bool CheckBobtailPoWFromOrderedProofs(std::vector<arith_uint256> proofs, arith_uint256 target, uint8_t k);
bool CheckSubBlockPoW(const CBlockHeader &header, const Consensus::Params &params, uint8_t k);
double GetKOSThreshold(arith_uint256 target, uint8_t k);
/*
 * Note that scaleFactor leads to a reduction in the scale parameter of the 
 * gamma distribution by the amount target/scaleFactor. The unit test
 * test_scaling_gamma shows that this is equivalent to reducing the mean
 * of the distribution by the same amount. Thus, if we scale both target
 * and pow by target/scaleFactor, then the result will be mathematically
 * equivalent to not scaling at all. The benefit of this approach is that
 * we can avoid calling getdouble() on very large arith_uint256.
 */
bool IsBelowKOSThreshold(arith_uint256 pow, arith_uint256 target, uint8_t k, int scaleFactor=DEFAULT_SCALE_FACTOR);
/*
 * Uses Theorem 3 from the NDSS Bobtail paper and binary search to
 * find the best value for k that delivers no more than the desired 
 * number of nodes in the dag (subblocks) with the given probability.
 */
uint32_t GetBestK(uint16_t desiredDagNodes, double probability);

#endif
