// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bobtail.h"
#include "bobtailblock.h"
#include "dag.h"

#include "net.h"

#include <boost/math/distributions/gamma.hpp>

bool IsSubBlockMalformed(const CSubBlock &subblock)
{
    if (subblock.IsNull())
    {
        return true;
    }
    // at a minimum a subblock needs a proofbase transaction to be valid
    if (subblock.vtx.size() == 0)
    {
        return true;
    }
    if (subblock.vtx[0]->IsProofBase() == false)
    {
        return true;
    }
    size_t size_vtx = subblock.vtx.size();
    for (size_t i = 1; i < size_vtx; ++i)
    {
        if (subblock.vtx[i]->IsProofBase())
        {
            return true;
        }
    }
    return false;
}

bool ProcessNewSubBlock(const CSubBlock &subblock)
{
    if (IsSubBlockMalformed(subblock) == false)
    {
        if (bobtailDagSet.Insert(subblock))
        {
            LOCK(cs_vNodes);
            for (CNode *pnode : vNodes)
            {
                pnode->PushInventory(CInv(MSG_SUBBLOCK, subblock.GetHash()));
            }
            return true;
        }
    }
    return false;
}

bool CheckBobtailPoW(CBobtailBlock block, const Consensus::Params &params, uint8_t k)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    if (k == 0)
        return true;

    if (block.vdag.size() < k)
        return false;

    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);

    if (fNegative || fOverflow)
    {
        LOG(WB, "Illegal value encountered when decoding target bits=%d\n", block.nBits);
        return false;
    }

    if (bnTarget > UintToArith256(params.powLimit))
    {
        LOG(WB, "Illegal target value bnTarget=%d for pow limit\n", bnTarget.getdouble());
        return false;
    }

    std::vector<CSubBlockRef> subblocks = block.vdag;
    std::vector<uint256> subblockHashes;
    for (auto subblock : subblocks)
    {
        subblockHashes.push_back(subblock->GetHash());
    }

    std::sort(subblockHashes.begin(), subblockHashes.end());
    std::vector<arith_uint256> lowestK;
    for (int i=0;i < k-1;i++)
    {
        lowestK.push_back(UintToArith256(subblockHashes[i]));
    }

    return CheckBobtailPoWFromOrderedProofs(lowestK, bnTarget, k);
}

bool CheckBobtailPoWFromOrderedProofs(std::vector<arith_uint256> proofs, arith_uint256 target, uint8_t k)
{
    arith_uint256 average(0);
    arith_uint256 kTarget(k);
    for (auto proof : proofs)
        average += proof;
    average /= kTarget;

    if (average < target)
        return true;

    return false;
}

bool CheckSubBlockPoW(const CBlockHeader &header, const Consensus::Params &params, uint8_t k)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;

    bnTarget.SetCompact(header.nBits, &fNegative, &fOverflow);

    if (fNegative || fOverflow)
    {
        LOG(WB, "Illegal value encountered when decoding target bits=%d\n", header.nBits);
        return false;
    }

    if (bnTarget > UintToArith256(params.powLimit))
    {
        LOG(WB, "Illegal target value bnTarget=%d for pow limit\n", bnTarget.getdouble());
        return false;
    }

    arith_uint256 pow = UintToArith256(header.GetHash());

    return IsBelowKOSThreshold(pow, bnTarget, k);
}

double GetKOSThreshold(arith_uint256 target, uint8_t k)
{
    if (k == 0)
        return 0.0;

    boost::math::gamma_distribution<> bobtail_gamma(k, target.getdouble());

    return quantile(bobtail_gamma, KOS_INCLUSION_PROB);
}

bool IsBelowKOSThreshold(arith_uint256 pow, arith_uint256 target, uint8_t k, int scaleFactor)
{
    if (k == 0)
        return true;

    // Scale everything down as though the target was only scaleFactor
    arith_uint256 scalar = target / arith_uint256(scaleFactor);
    arith_uint256 scaledTarget = arith_uint256(scaleFactor);
    arith_uint256 scaledPow = pow / scalar;

    boost::math::gamma_distribution<> bobtail_gamma(k, scaledTarget.getdouble());

    return cdf(bobtail_gamma, scaledPow.getdouble()) <= KOS_INCLUSION_PROB;
}

uint32_t GetBestK(uint16_t desiredDagNodes, double probability)
{
    uint32_t kLow = 0;
    uint32_t kHigh = std::numeric_limits<uint16_t>::max();

    while (kHigh - kLow > 1)
    {
        uint32_t kMid = kLow + (kHigh-kLow) / 2;
        boost::math::gamma_distribution<> gammaMid(kMid, 1);

        if (quantile(gammaMid, probability) < desiredDagNodes)
            kLow = kMid;
        else
            kHigh = kMid;
    }

    return kLow;
}
