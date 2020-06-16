// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BOBTAIL_DAG_H
#define BITCOIN_BOBTAIL_DAG_H

#include "uint256.h"
#include "subblock.h"
#include "sync.h"

#include <deque>
#include <queue>
#include <set>

class CDagNode
{
public:
    uint256 hash; // the weakblock hash that is this node
    int16_t dag_id; // cannot be negative

    CSubBlock subblock;

    std::set<CDagNode*> ancestors; // should point to the nodes of the parentHashes
    std::set<CDagNode*> descendants; // points to the nodes of the children

private:
    CDagNode(){} // disable default constructor

public:
    CDagNode(CSubBlock _subblock)
    {
        hash = _subblock.GetHash();
        subblock = _subblock;
        dag_id = -1;
    }

    void AddAncestor(CDagNode* ancestor);
    void AddDescendant(CDagNode* descendant);
    bool IsBase();
    bool IsTip();
    uint16_t GetNodeScore();
    bool IsValid();
};

class CBobtailDag
{
friend class CBobtailDagSet;

protected:
    uint16_t id; // should match the index of the vector in which this dag is in the dag set
    std::deque<CDagNode*> _dag;

public:
    // output spent, the tx hash it was spent in
    std::map<COutPoint, uint256> spent_outputs;
    uint64_t score;
    std::set<int16_t>incompatible_dags;

private:
    CBobtailDag(){} // disable default constructor

protected:
    void SetId(int16_t new_id);
    bool CheckForCompatibility(CDagNode* newNode);
    void UpdateCompatibility(const int16_t &new_id, const std::set<int16_t> &old_ids);

public:
    CBobtailDag(uint16_t _id, CDagNode* first_node)
    {
        id = _id;
        Insert(first_node);
    }
    bool Insert(CDagNode* new_node);

};

class CBobtailDagSet
{
protected:
    CRecursiveSharedCriticalSection cs_dagset;

    std::vector<CBobtailDag> vdags;
    std::map<uint256, CDagNode> mapAllNodes;

private:
    void SetNewIds(std::priority_queue<int16_t> &removed_ids);

protected:
    void CreateNewDag(CDagNode *newNode);
    bool MergeDags(std::set<int16_t> &tree_ids, int16_t &new_id);

public:
    CBobtailDagSet()
    {
        Clear();
    }

    void Clear();

    size_t Size();

    bool Find(const uint256 &hash, CSubBlock &subblock);
    bool Contains(const uint256 &hash);
    bool Insert(const CSubBlock &sub_block);
    void TemporalSort();
    bool IsTemporallySorted();
    bool GetBestDag(std::set<CDagNode*> &dag);
    std::vector<uint256> GetTips();
};

extern CBobtailDagSet bobtailDagSet;

#endif
