// Copyright (c) 2018-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MEMPOOL_SYNC_H
#define BITCOIN_MEMPOOL_SYNC_H

#include "blockrelay/blockrelay_common.h"
#include "blockrelay/graphene.h"
#include "consensus/consensus.h"

#include <chrono>

const uint64_t DEFAULT_MEMPOOL_SYNC_MIN_VERSION_SUPPORTED = 0;
const uint64_t DEFAULT_MEMPOOL_SYNC_MAX_VERSION_SUPPORTED = 0;
// arbitrary entropy passed to CGrapheneSet an used for IBLT
const uint32_t IBLT_ENTROPY = 13;
// any value greater than 2 will use SipHash
const uint64_t SHORT_ID_VERSION = 2;
// frequency of synchronization (per peer) in milliseconds
const int64_t MEMPOOLSYNC_FREQ_US = 30 * 1e6;
const int64_t MEMPOOLSYNC_FREQ_GRACE_US = 5 * 1e6;
// Use CVariableFastFilter if true, otherwise use CBloomFilter
const bool COMPUTE_OPTIMIZED = true;

class CMempoolSyncState
{
public:
    std::chrono::time_point<std::chrono::high_resolution_clock> lastUpdated;
    uint64_t shorttxidk0;
    uint64_t shorttxidk1;
    bool completed;

public:
    CMempoolSyncState(std::chrono::time_point<std::chrono::high_resolution_clock> _lastUpdated,
        uint64_t _shorttxidk0,
        uint64_t _shorttxidk1,
        bool _completed)
        : lastUpdated(_lastUpdated), shorttxidk0(_shorttxidk0), shorttxidk1(_shorttxidk1), completed(_completed)
    {
    }
    CMempoolSyncState()
        : lastUpdated(std::chrono::high_resolution_clock::now()), shorttxidk0(0), shorttxidk1(0), completed(false)
    {
    }
};

extern std::map<CNode *, CMempoolSyncState> mempoolSyncRequested;
extern std::map<CNode *, CMempoolSyncState> mempoolSyncResponded;

class CMempoolSyncInfo
{
public:
    uint64_t nTxInMempool;
    uint64_t nRemainingMempoolBytes;
    uint64_t shorttxidk0;
    uint64_t shorttxidk1;
    uint64_t nSatoshiPerK;

public:
    CMempoolSyncInfo(uint64_t nTxInMempool,
        uint64_t nRemainingMempoolBytes,
        uint64_t shorttxidk0,
        uint64_t shorttxidk1,
        uint64_t nSatoshiPerK);
    CMempoolSyncInfo();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(nTxInMempool);
        READWRITE(nRemainingMempoolBytes);
        READWRITE(shorttxidk0);
        READWRITE(shorttxidk1);
        READWRITE(nSatoshiPerK);
    }
};

class CMempoolSync
{
public:
    uint64_t nSenderMempoolTxs;
    std::shared_ptr<CGrapheneSet> pGrapheneSet;
    uint64_t version;

public:
    CMempoolSync(std::vector<uint256> mempoolTxHashes,
        uint64_t nReceiverMemPoolTx,
        uint64_t nSenderMempoolPlusBlock,
        uint64_t shorttxidk0,
        uint64_t shorttxidk1,
        uint64_t _version);
    CMempoolSync() : nSenderMempoolTxs(0), pGrapheneSet(nullptr), version(0) {}
    CMempoolSync(uint64_t _version) : nSenderMempoolTxs(0), pGrapheneSet(nullptr) {}
    ~CMempoolSync();

    static inline uint64_t GetGrapheneSetVersion(uint64_t grapheneBlockVersion) { return 4; }
    /**
     * Handle an incoming MempoolSync
     * @param[in]  vRecv        The raw binary message
     * @param[in]  pFrom        The node the message was from
     * @param[in]  strCommand   The message kind
     * @return True if handling succeeded
     */
    static bool ReceiveMempoolSync(CDataStream &vRecv, CNode *pfrom, std::string strCommand);
    bool process(CNode *pfrom);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(COMPACTSIZE(version));
        READWRITE(nSenderMempoolTxs);
        if (nSenderMempoolTxs > (maxMessageSizeMultiplier * excessiveBlockSize / MIN_TX_SIZE))
            throw std::runtime_error("nSenderMempoolTxs exceeds threshold for excessive block txs");
        if (!pGrapheneSet)
        {
            pGrapheneSet = std::make_shared<CGrapheneSet>(
                CGrapheneSet(CMempoolSync::GetGrapheneSetVersion(version), COMPUTE_OPTIMIZED));
        }
        READWRITE(*pGrapheneSet);
    }

    bool process(CNode *pfrom, std::string strCommand, std::shared_ptr<CBlockThinRelay> pblock);
};

class CRequestMempoolSyncTx
{
public:
    std::set<uint64_t> setCheapHashesToRequest; // map of missing transactions

public:
    CRequestMempoolSyncTx(std::set<uint64_t> &_setCheapHashesToRequest)
        : setCheapHashesToRequest(_setCheapHashesToRequest){};
    CRequestMempoolSyncTx() {}
    /**
     * Handle an incoming request for missing graphene block transactions
     * @param[in] vRecv        The raw binary message
     * @param[in] pFrom        The node the message was from
     * @return True if handling succeeded
     */
    static bool HandleMessage(CDataStream &vRecv, CNode *pfrom);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(setCheapHashesToRequest);
    }
};

class CMempoolSyncTx
{
public:
    std::vector<CTransactionRef> vTx;

public:
    CMempoolSyncTx(std::vector<CTransactionRef> &_vTx) : vTx(_vTx){};
    CMempoolSyncTx(){};

    /**
     * Handle receiving a list of missing mempool sync transactions from a prior request
     * @param[in] vRecv        The raw binary message
     * @param[in] pFrom        The node the message was from
     * @return True if handling succeeded
     */
    static bool HandleMessage(CDataStream &vRecv, CNode *pfrom);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(vTx);
    }
};

bool HandleMempoolSyncRequest(CDataStream &vRecv, CNode *pfrom);
void GetMempoolTxHashes(std::vector<uint256> &mempoolTxHashes);
CMempoolSyncInfo GetMempoolSyncInfo();
uint64_t NegotiateMempoolSyncVersion(CNode *pfrom);
CNode *SelectMempoolSyncPeer(std::vector<CNode *> vNodesCopy);

#endif // BITCOIN_MEMPOOL_SYNC_H
