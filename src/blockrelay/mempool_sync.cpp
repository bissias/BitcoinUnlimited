// Copyright (c) 2018-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockrelay/mempool_sync.h"
#include "dosman.h"
#include "txadmission.h"
#include "txmempool.h"
#include "txorphanpool.h"
#include "util.h"
#include "xversionkeys.h"

extern CTxMemPool mempool;
extern CTweak<uint64_t> mempoolSyncMinVersionSupported;
extern CTweak<uint64_t> mempoolSyncMaxVersionSupported;

CMempoolSyncInfo::CMempoolSyncInfo(uint64_t _nTxInMempool,
    uint64_t _nRemainingMempoolBytes,
    uint64_t _seed,
    uint64_t _nSatoshiPerK)
    : nTxInMempool(_nTxInMempool), nRemainingMempoolBytes(_nRemainingMempoolBytes), seed(_seed),
      nSatoshiPerK(_nSatoshiPerK)
{
}
CMempoolSyncInfo::CMempoolSyncInfo()
{
    this->nTxInMempool = 0;
    this->nRemainingMempoolBytes = 0;
    this->seed = 0;
    this->nSatoshiPerK = 0;
}

CMempoolSync::CMempoolSync(std::vector<uint256> mempoolTxHashes,
    uint64_t nReceiverMemPoolTx,
    uint64_t nSenderMempoolPlusBlock,
    uint64_t _version)
    : version(_version), nSenderMempoolTxs(0)
{
    uint64_t grapheneSetVersion = CMempoolSync::GetGrapheneSetVersion(version);
    nSenderMempoolTxs = mempoolTxHashes.size();

    // TODO: consider making SHORTTXIDK0, SHORTTXIDK1, and IBLT_ENTROPY random
    pGrapheneSet = std::make_shared<CGrapheneSet>(CGrapheneSet(nReceiverMemPoolTx, nSenderMempoolPlusBlock,
        mempoolTxHashes, SHORTTXIDK0, SHORTTXIDK1, grapheneSetVersion, IBLT_ENTROPY, COMPUTE_OPTIMIZED, false));
}

CMempoolSync::~CMempoolSync() { pGrapheneSet = nullptr; }
bool HandleMempoolSyncRequest(CDataStream &vRecv, CNode *pfrom)
{
    LOG(MPOOLSYNC, "Handling mempool sync request from peer %s\n", pfrom->GetLogName());
    CMempoolSyncInfo mempoolinfo;
    CInv inv;
    vRecv >> inv >> mempoolinfo;

    // Message consistency checking
    if (!(inv.type == MSG_MEMPOOLSYNC))
    {
        dosMan.Misbehaving(pfrom, 100);
        return error("invalid GET_MEMPOOLSYNC message type=%u\n", inv.type);
    }

    // TODO: Add some sort of DoS detection

    if (inv.type == MSG_MEMPOOLSYNC)
    {
        std::vector<uint256> mempoolTxHashes;
        // cycle through mempool txs in order of ancestor_score
        {
            READLOCK(mempool.cs);

            int64_t nRemainingMempoolBytes = mempoolinfo.nRemainingMempoolBytes;
            typename CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator it =
                mempool.mapTx.get<ancestor_score>().begin();
            for (; it != mempool.mapTx.get<ancestor_score>().end() && nRemainingMempoolBytes > 0; ++it)
            {
                uint64_t nTxSize = it->GetTx().GetTxSize();
                uint64_t nFee = it->GetFee();
                uint64_t nSatoshiPerK = (uint64_t)(1000 * nFee / (double)nTxSize);

                // Skip tx if fee rate is too low
                if (nSatoshiPerK < mempoolinfo.nSatoshiPerK)
                    continue;

                mempoolTxHashes.push_back(it->GetTx().GetHash());
                nRemainingMempoolBytes -= nTxSize;
            }
        }

        if (mempoolTxHashes.size() == 0)
        {
            LOG(MPOOLSYNC, "mempool is empty; aborting mempool sync with peer %s\n", pfrom->GetLogName());
            return true;
        }

        uint64_t nBothMempools = mempoolTxHashes.size() + mempoolinfo.nTxInMempool;
        CMempoolSync mempoolSync(
            mempoolTxHashes, mempoolinfo.nTxInMempool, nBothMempools, NegotiateMempoolSyncVersion(pfrom));

        pfrom->PushMessage(NetMsgType::MEMPOOLSYNC, mempoolSync);
        LOG(MPOOLSYNC, "Sent mempool sync to peer %s using version %d\n", pfrom->GetLogName(), mempoolSync.version);
    }
    else
    {
        dosMan.Misbehaving(pfrom, 100);

        return false;
    }

    return true;
}

/**
 * Handle an incoming mempool synchronization payload
 */
bool CMempoolSync::ReceiveMempoolSync(CDataStream &vRecv, CNode *pfrom, std::string strCommand)
{
    // Deserialize mempool sync payload and store a block to reconstruct
    CMempoolSync tmp;
    vRecv >> tmp;
    auto mempoolSync = std::make_shared<CMempoolSync>(std::forward<CMempoolSync>(tmp));

    LOG(MPOOLSYNC, "Received mempool sync from peer %s\n", pfrom->GetLogName());

    // Do not process unrequested mempool sync.
    if (!(mempoolSyncRequested.count(pfrom) == 1))
    {
        dosMan.Misbehaving(pfrom, 10);
        return error("Received unrequested mempool sync from peer %s\n", pfrom->GetLogName());
    }

    return mempoolSync->process(pfrom);
}

bool CMempoolSync::process(CNode *pfrom)
{
    std::set<uint256> passingTxHashes;
    std::map<uint64_t, uint256> mapPartialTxHash;
    std::set<uint64_t> setHashesToRequest;

    std::vector<uint256> mempoolTxHashes;
    GetMempoolTxHashes(mempoolTxHashes);

    for (const uint256 &hash : mempoolTxHashes)
    {
        uint64_t cheapHash = GetShortID(SHORTTXIDK0, SHORTTXIDK1, hash, SHORT_ID_VERSION);
        mapPartialTxHash.insert(std::make_pair(cheapHash, hash));
    }

    try
    {
        std::vector<uint64_t> blockCheapHashes = pGrapheneSet->Reconcile(mapPartialTxHash);

        // Sort out what hashes we have from the complete set of cheapHashes
        for (size_t i = 0; i < blockCheapHashes.size(); i++)
        {
            uint64_t cheapHash = blockCheapHashes[i];

            const auto &elem = mapPartialTxHash.find(cheapHash);
            if (elem == mapPartialTxHash.end())
                setHashesToRequest.insert(cheapHash);
        }
    }
    catch (const std::runtime_error &e)
    {
        LOG(MPOOLSYNC, "Mempool sync failed for peer %s. Graphene set could not be reconciled: %s\n",
            pfrom->GetLogName(), e.what());
    }

    LOG(MPOOLSYNC, "Mempool sync received: %d total txns, waiting for: %d from peer %s\n", nSenderMempoolTxs,
        setHashesToRequest.size(), pfrom->GetLogName());

    // If there are any missing hashes or transactions then we request them here.
    if (setHashesToRequest.size() > 0)
    {
        CRequestMempoolSyncTx mempoolSyncTx(setHashesToRequest);
        pfrom->PushMessage(NetMsgType::GET_MEMPOOLSYNCTX, mempoolSyncTx);
        LOG(MPOOLSYNC, "Requesting to sync %d missing transactions from %s\n", setHashesToRequest.size(),
            pfrom->GetLogName());

        return true;
    }

    // We now have all the transactions that are in this sync
    LOG(MPOOLSYNC, "Completeing mempool sync with %s; no missing transactions\n", pfrom->GetLogName());

    return true;
}

bool CRequestMempoolSyncTx::HandleMessage(CDataStream &vRecv, CNode *pfrom)
{
    CRequestMempoolSyncTx reqMempoolSyncTx;
    vRecv >> reqMempoolSyncTx;

    // Message consistency checking
    if (reqMempoolSyncTx.setCheapHashesToRequest.empty())
    {
        dosMan.Misbehaving(pfrom, 100);
        return error("Incorrectly constructed getmemsynctx received.  Banning peer=%s", pfrom->GetLogName());
    }

    // TODO: Add some sort of DoS detection

    LOG(MPOOLSYNC, "Received getmemsynctx from peer=%s requesting %d transactions\n", pfrom->GetLogName(),
        reqMempoolSyncTx.setCheapHashesToRequest.size());

    std::vector<uint256> mempoolTxHashes;
    GetMempoolTxHashes(mempoolTxHashes);

    // Locate transactions requested
    // Note that only those still in the mempool will be located
    std::vector<CTransaction> vTx;
    for (auto &hash : mempoolTxHashes)
    {
        uint64_t cheapHash = GetShortID(SHORTTXIDK0, SHORTTXIDK1, hash, SHORT_ID_VERSION);

        if (reqMempoolSyncTx.setCheapHashesToRequest.count(cheapHash) == 0)
            continue;

        vTx.push_back(*(mempool.get(hash).get()));
    }

    LOG(MPOOLSYNC, "Sending %d mempool sync transactions to peer=%s\n", vTx.size(), pfrom->GetLogName());

    CMempoolSyncTx mempoolSyncTx(vTx);
    pfrom->PushMessage(NetMsgType::MEMPOOLSYNCTX, mempoolSyncTx);

    return true;
}

bool CMempoolSyncTx::HandleMessage(CDataStream &vRecv, CNode *pfrom)
{
    std::string strCommand = NetMsgType::MEMPOOLSYNCTX;
    size_t msgSize = vRecv.size();
    CMempoolSyncTx mempoolSyncTx;
    vRecv >> mempoolSyncTx;

    // Do not process unrequested memsynctx.
    if (mempoolSyncRequested.count(pfrom) == 0)
    {
        dosMan.Misbehaving(pfrom, 10);
        return error("Received memsynctx from peer %s but mempool sync is not in progress", pfrom->GetLogName());
    }

    LOG(MPOOLSYNC, "Received memsynctx from peer=%s; adding %d transactions to mempool\n", pfrom->GetLogName(),
        mempoolSyncTx.vTx.size());

    size_t idx = 0;
    for (const CTransaction &tx : mempoolSyncTx.vTx)
    {
        CTxInputData inputData;
        inputData.tx = std::make_shared<CTransaction>(tx);
        inputData.nodeId = pfrom->id;
        EnqueueTxForAdmission(inputData);
    }

    LOG(MPOOLSYNC, "Recovered %d txs from peer=%s via mempool sync\n", mempoolSyncTx.vTx.size(), pfrom->GetLogName());

    return true;
}

void GetMempoolTxHashes(std::vector<uint256> &mempoolTxHashes)
{
    {
        READLOCK(orphanpool.cs);
        for (auto &kv : orphanpool.mapOrphanTransactions)
        {
            mempoolTxHashes.push_back(kv.first);
        }
    }

    // We don't have to keep the lock on mempool.cs here to do mempool.queryHashes
    // but we take the lock anyway so we don't have to re-lock again later.
    std::vector<uint256> memPoolHashes;
    mempool.queryHashes(memPoolHashes);

    for (const uint256 &hash : memPoolHashes)
    {
        mempoolTxHashes.push_back(hash);
    }
}

CMempoolSyncInfo GetMempoolSyncInfo()
{
    // We need the number of transactions in the mempool and orphanpools but also the number
    // in the txCommitQ that have been processed and valid, and which will be in the mempool shortly.
    uint64_t nCommitQ = 0;
    {
        boost::unique_lock<boost::mutex> lock(csCommitQ);
        nCommitQ = txCommitQ->size();
    }

    uint64_t nTxInMempool = mempool.size() + orphanpool.GetOrphanPoolSize() + nCommitQ;
    uint64_t nMempoolMaxTxBytes = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    uint64_t seed = GetRand(std::numeric_limits<uint64_t>::max());
    uint64_t nSatoshiPerK = minRelayTxFee.GetFeePerK();

    uint64_t nRemainingMempoolTxBytes = nMempoolMaxTxBytes;
    {
        READLOCK(mempool.cs);
        for (const CTxMemPoolEntry &e : mempool.mapTx)
        {
            nRemainingMempoolTxBytes += e.GetTx().GetTxSize();
        }
    }

    return CMempoolSyncInfo(nTxInMempool, nRemainingMempoolTxBytes, seed, nSatoshiPerK);
}

uint64_t NegotiateMempoolSyncVersion(CNode *pfrom)
{
    uint64_t peerMin = pfrom->xVersion.as_u64c(XVer::BU_MEMPOOL_SYNC_MIN_VERSION_SUPPORTED);
    uint64_t selfMin = mempoolSyncMinVersionSupported.Value();
    uint64_t peerMax = pfrom->xVersion.as_u64c(XVer::BU_MEMPOOL_SYNC_MAX_VERSION_SUPPORTED);
    uint64_t selfMax = mempoolSyncMaxVersionSupported.Value();

    uint64_t upper = (uint64_t)std::min(peerMax, selfMax);
    uint64_t lower = (uint64_t)std::max(peerMin, selfMin);

    if (lower > upper)
        throw std::runtime_error("Sender and receiver support incompatible mempool sync versions");

    return upper;
}
