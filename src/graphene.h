// Copyright (c) 2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_GRAPHENE_H
#define BITCOIN_GRAPHENE_H

#include "bloom.h"
#include "consensus/validation.h"
#include "iblt.h"
#include "primitives/block.h"
#include "protocol.h"
#include "serialize.h"
#include "stat.h"
#include "sync.h"
#include "uint256.h"
#include <atomic>
#include <cmath>
#include <vector>

// c from graphene paper
const double BLOOM_OVERHEAD_FACTOR = 8 * pow(log(2.0), 2.0);
// tau from graphene paper
const double IBLT_OVERHEAD_FACTOR = 16.5;
const uint8_t IBLT_CELL_MINIMUM = 3;
const uint8_t IBLT_VALUE_SIZE = 0;
const std::vector<uint8_t> IBLT_NULL_VALUE = {};

class CDataStream;
class CNode;

class CMemPoolInfo
{
public:
    uint64_t nTx;

public:
    CMemPoolInfo(uint64_t nTx);
    CMemPoolInfo();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(nTx);
    }
};

class CGrapheneBlock
{
public:
    CBlockHeader header;
    std::vector<uint256> vTxHashes; // List of all transactions id's in the block
    std::vector<uint64_t> txOrder;
    unsigned char txOrderSeed;
    uint64_t nBlockTxs;
    CBloomFilter *pGrapheneBlockFilter;
    CIblt *pGrapheneBlockIblt;

public:
    CGrapheneBlock(const CBlock &block, uint64_t nReceiverMemPoolTx);
    CGrapheneBlock() : pGrapheneBlockFilter(nullptr), pGrapheneBlockIblt(nullptr) {}
    ~CGrapheneBlock();
    /**
     * Handle an incoming Graphene block
     * Once the block is validated apart from the Merkle root, forward the Xpedited block with a hop count of nHops.
     * @param[in]  vRecv        The raw binary message
     * @param[in]  pFrom        The node the message was from
     * @param[in]  strCommand   The message kind
     * @param[in]  nHops        On the wire, nHops is zero for an incoming Graphene block
     * @return True if handling succeeded
     */
    static bool HandleMessage(CDataStream &vRecv, CNode *pfrom, std::string strCommand, unsigned nHops);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(header);
        READWRITE(txOrder);
        READWRITE(txOrderSeed);
        READWRITE(nBlockTxs);
        if (!pGrapheneBlockFilter)
            pGrapheneBlockFilter = new CBloomFilter();
        READWRITE(*pGrapheneBlockFilter);
        if (!pGrapheneBlockIblt)
            pGrapheneBlockIblt = new CIblt();
        READWRITE(*pGrapheneBlockIblt);
    }
    CInv GetInv() { return CInv(MSG_BLOCK, header.GetHash()); }
    bool process(CNode *pfrom, int nSizeGrapheneBlock, std::string strCommand);
    bool CheckBlockHeader(const CBlockHeader &block, CValidationState &state);
};

// This class is used to respond to requests for missing transactions after sending an Graphene block.
// It is filled with the requested transactions in order.
class CGrapheneBlockTx
{
public:
    /** Public only for unit testing */
    uint256 blockhash;
    std::vector<CTransaction> vMissingTx; // map of missing transactions

public:
    CGrapheneBlockTx(uint256 blockHash, std::vector<CTransaction> &vTx);
    CGrapheneBlockTx() {}
    /**
     * Handle receiving a list of missing graphene block transactions from a prior request
     * @param[in] vRecv        The raw binary message
     * @param[in] pFrom        The node the message was from
     * @return True if handling succeeded
     */
    static bool HandleMessage(CDataStream &vRecv, CNode *pfrom);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(blockhash);
        READWRITE(vMissingTx);
    }
};

// This class is used for requests for still missing transactions after processing a "graphene" message.
// This class uses a 64bit hash as opposed to the normal 256bit hash.  The target is expected to reply with
// a serialized CGrapheneBlockTx response message.
class CRequestGrapheneBlockTx
{
public:
    /** Public only for unit testing */
    uint256 blockhash;
    std::set<uint64_t> setCheapHashesToRequest; // map of missing transactions

public:
    CRequestGrapheneBlockTx(uint256 blockHash, std::set<uint64_t> &setHashesToRequest);
    CRequestGrapheneBlockTx() {}
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
        READWRITE(blockhash);
        READWRITE(setCheapHashesToRequest);
    }
};

// This class stores statistics for graphene block derived protocols.
class CGrapheneBlockData
{
private:
    /* The sum total of all bytes for graphene blocks currently in process of being reconstructed */
    std::atomic<uint64_t> nGrapheneBlockBytes{0};

    CCriticalSection cs_mapGrapheneBlockTimer; // locks mapGrapheneBlockTimer
    std::map<uint256, uint64_t> mapGrapheneBlockTimer;

    CCriticalSection cs_graphenestats; // locks everything below this point

    CStatHistory<uint64_t> nOriginalSize;
    CStatHistory<uint64_t> nGrapheneSize;
    CStatHistory<uint64_t> nBlocks;
    CStatHistory<uint64_t> nMempoolLimiterBytesSaved;
    CStatHistory<uint64_t> nTotalMemPoolInfoBytes;
    std::map<int64_t, std::pair<uint64_t, uint64_t> > mapGrapheneBlocksInBound;
    std::map<int64_t, std::pair<uint64_t, uint64_t> > mapGrapheneBlocksOutBound;
    std::map<int64_t, uint64_t> mapMemPoolInfoOutBound;
    std::map<int64_t, uint64_t> mapMemPoolInfoInBound;
    std::map<int64_t, double> mapGrapheneBlockResponseTime;
    std::map<int64_t, double> mapGrapheneBlockValidationTime;
    std::map<int64_t, int> mapGrapheneBlocksInBoundReRequestedTx;

    /**
        Add new entry to statistics array; also removes old timestamps
        from statistics array using expireStats() below.
        @param [statsMap] a statistics array
        @param [value] the value to insert for the current time
     */
    template <class T>
    void updateStats(std::map<int64_t, T> &statsMap, T value);

    /**
       Expire old statistics in given array (currently after one day).
       Uses getTimeForStats() virtual method for timing. */
    template <class T>
    void expireStats(std::map<int64_t, T> &statsMap);

    /**
      Calculate average of long long values in given map. Return 0 for no entries.
      Expires values before calculation. */
    double average(std::map<int64_t, uint64_t> &map);

protected:
    //! Virtual method so it can be overridden for better unit testing
    virtual int64_t getTimeForStats() { return GetTimeMillis(); }
public:
    void UpdateInBound(uint64_t nGrapheneBlockSize, uint64_t nOriginalBlockSize);
    void UpdateOutBound(uint64_t nGrapheneBlockSize, uint64_t nOriginalBlockSize);
    void UpdateOutBoundMemPoolInfo(uint64_t nMemPoolInfoSize);
    void UpdateInBoundMemPoolInfo(uint64_t nMemPoolInfoSize);
    void UpdateResponseTime(double nResponseTime);
    void UpdateValidationTime(double nValidationTime);
    void UpdateInBoundReRequestedTx(int nReRequestedTx);
    void UpdateMempoolLimiterBytesSaved(unsigned int nBytesSaved);
    std::string ToString();
    std::string InBoundPercentToString();
    std::string OutBoundPercentToString();
    std::string InBoundMemPoolInfoToString();
    std::string OutBoundMemPoolInfoToString();
    std::string ResponseTimeToString();
    std::string ValidationTimeToString();
    std::string ReRequestedTxToString();
    std::string MempoolLimiterBytesSavedToString();

    bool CheckGrapheneBlockTimer(uint256 hash);
    void ClearGrapheneBlockTimer(uint256 hash);

    void ClearGrapheneBlockData(CNode *pfrom);
    void ClearGrapheneBlockData(CNode *pfrom, uint256 hash);

    uint64_t AddGrapheneBlockBytes(uint64_t, CNode *pfrom);
    void DeleteGrapheneBlockBytes(uint64_t, CNode *pfrom);
    void ResetGrapheneBlockBytes();
    uint64_t GetGrapheneBlockBytes();
};
extern CGrapheneBlockData graphenedata; // Singleton class


bool HaveConnectGrapheneNodes();
bool HaveGrapheneNodes();
bool IsGrapheneBlockEnabled();
bool CanGrapheneBlockBeDownloaded(CNode *pto);
void ConnectToGrapheneBlockNodes();
void CheckNodeSupportForGrapheneBlocks();
bool ClearLargestGrapheneBlockAndDisconnect(CNode *pfrom);
void ClearGrapheneBlockInFlight(CNode *pfrom, uint256 hash);
void AddGrapheneBlockInFlight(CNode *pfrom, uint256 hash);
void SendGrapheneBlock(CBlock &block, CNode *pfrom, const CInv &inv);
bool IsGrapheneBlockValid(CNode *pfrom, const CBlockHeader &header);
bool HandleGrapheneBlockRequest(CDataStream &vRecv, CNode *pfrom, const CChainParams &chainparams);
double OptimalSymDiff(uint64_t nBlockTxs, uint64_t nReceiverMemPoolTx);
CMemPoolInfo GetGrapheneMempoolInfo();
uint256 GetSalt(unsigned char seed);

#endif // BITCOIN_GRAPHENE_H