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

bool IsSubBlockMalformed(const CSubBlock &subblock);
bool ProcessNewSubBlock(const CSubBlock &subblock);
bool CheckBobtailPoW(CBobtailBlock block, const Consensus::Params &params, uint8_t k);
bool CheckBobtailPoWFromOrderedProofs(std::vector<arith_uint256> proofs, arith_uint256 target, uint8_t k);
bool CheckSubBlockPoW(const CBlockHeader header, const Consensus::Params &params, uint8_t k);
double GetKOSThreshold(arith_uint256 target, uint8_t k);

#endif
