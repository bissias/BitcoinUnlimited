// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dag.h"

#include "consensus/consensus.h"

void CDagNode::AddAncestor(CDagNode* ancestor)
{
    ancestors.emplace(ancestor);
}

void CDagNode::AddDescendant(CDagNode* descendant)
{
    descendants.emplace(descendant);
}

// there is nothing below it
bool CDagNode::IsBase()
{
    return ancestors.empty();
}

// there is nothing above it
bool CDagNode::IsTip()
{
    return descendants.empty();
}

bool CDagNode::IsValid()
{
    return (subblock.IsNull() == false && dag_id >= 0);
}

void CBobtailDag::SetId(int16_t new_id)
{
    id = new_id;
}

bool CBobtailDag::CheckForCompatibility(CDagNode* newNode)
{
    // we are already incompatible with this node, no need to check its inputs
    if (incompatible_dags.count(newNode->dag_id))
    {
        return false;
    }
    for (auto &tx : newNode->subblock.vtx)
    {
        for (auto &input : tx->vin)
        {
            if (spent_outputs.count(input.prevout) != 0)
            {
                if (spent_outputs[input.prevout] != tx->GetHash())
                {
                    // only add it to incompatible_dags if we are not checking
                    // if the node can be added to this dag
                    if (id != newNode->dag_id)
                    {
                        incompatible_dags.emplace(newNode->dag_id);
                    }
                    return false;
                }
            }
        }
    }
    return true;
}

void CBobtailDag::UpdateCompatibility(const int16_t &new_id, const std::set<int16_t> &old_ids)
{
    // the old_ids are being merged into a dag with the new_id. This merge means these dags
    // were compatible. if a given dag was incompatible with one of the old_ids it will be
    // incompatible with the new id.
    // Go through the dags and replace any incompatible dag entrys with an old_id with the
    // new id
    for (auto &old_id : old_ids)
    {
        if (incompatible_dags.count(old_id))
        {
            // we can emplace multiple times, elements in a set are always unique
            incompatible_dags.emplace(new_id);
            // we added the new id to the incompatible list, erase the old id
            incompatible_dags.erase(old_id);
        }
    }
}

void CBobtailDag::UpdateDagScore()
{
    // keep track of what has been mapNodeScore
    std::map<CDagNode*, uint64_t> mapNodeScore;
    // build out the dag by level, a nodes level is determined by
    // its shortest path to a base
    std::vector<std::set<CDagNode*> > leveled_dag;
    // first find the bases
    leveled_dag.emplace_back();
    bool do_another_level = false;
    // there is always at least 1 node in a dag
    for (auto &node : _dag)
    {
        if (node->IsBase())
        {
            leveled_dag[0].emplace(node);
            mapNodeScore.emplace(node, 1);
            if (node->descendants.empty() == false)
            {
                do_another_level = true;
            }
        }
    }
    while (do_another_level == true)
    {
        size_t search_index = leveled_dag.size() - 1;
        // add another level
        leveled_dag.emplace_back();
        do_another_level = false;
        for (auto &node : leveled_dag[search_index])
        {
            for (auto &desc : node->descendants)
            {
                if (mapNodeScore.count(desc) == 0)
                {
                    mapNodeScore.emplace(desc, 1);
                    leveled_dag.back().emplace(desc);
                    if (desc->IsTip() == false)
                    {
                        do_another_level = true;
                    }
                }
            }
        }
    }
    // calculate the score
    uint16_t total_score = 0;
    std::vector<std::set<CDagNode*> >::reverse_iterator riter = leveled_dag.rbegin();
    size_t depth = 1;
    while (riter != leveled_dag.rend())
    {
        for (auto &node : *riter)
        {
            uint64_t node_score = 1;
            for (auto &desc : node->descendants)
            {
                auto iter = mapNodeScore.find(desc);
                if (iter != mapNodeScore.end())
                {
                    node_score = node_score + (iter->second * depth);
                }
            }
            total_score = total_score + node_score;
            auto this_node = mapNodeScore.find(node);
            if (this_node != mapNodeScore.end())
            {
                this_node->second = node_score;
            }
        }
        ++riter;
        ++depth;
    }
    score = total_score;
}

bool CBobtailDag::Insert(CDagNode* new_node)
{
    std::map<COutPoint, uint256> new_spends;
    for (auto &tx : new_node->subblock.vtx)
    {
        if (tx->IsProofBase() == false)
        {
            for (auto &input : tx->vin)
            {
                // TODO : change to contains in c++17
                if (spent_outputs.count(input.prevout) != 0)
                {
                    if (spent_outputs[input.prevout] != tx->GetHash())
                    {
                        return false;
                    }
                }
                new_spends.emplace(input.prevout, tx->GetHash());
            }
        }
    }
    // change to merge in c++17
    spent_outputs.insert(new_spends.begin(), new_spends.end());
    _dag.emplace_back(new_node);

    UpdateDagScore();

    return true;
}

void CBobtailDagSet::SetNewIds(std::priority_queue<int16_t> &removed_ids)
{
    RECURSIVEWRITELOCK(cs_dagset);
    int16_t last_value;
    for (auto riter = vdags.rbegin(); riter != vdags.rend(); ++riter)
    {
        last_value = removed_ids.top();
        // TODO : dont use assert here
        assert(riter->id != last_value);
        if (riter->id > last_value)
        {
            riter->id = riter->id - removed_ids.size();
        }
        else // <
        {
            removed_ids.pop();
            riter->id = riter->id - removed_ids.size();
        }
        if (removed_ids.empty())
        {
            break;
        }
    }
    // do a check to ensure everything lines up
    for (size_t i = 0; i < vdags.size(); ++i)
    {
        // TODO : dont use assert here
        assert(i == vdags[i].id);
        for (auto &node : vdags[i]._dag)
        {
            node->dag_id = i;
        }
    }
}

void CBobtailDagSet::CreateNewDag(CDagNode *newNode)
{
    RECURSIVEWRITELOCK(cs_dagset);
    int16_t new_id = vdags.size();
    newNode->dag_id = new_id;
    vdags.emplace_back(new_id, newNode);
    for (auto &dag : vdags)
    {
        dag.CheckForCompatibility(newNode);
    }
}

bool CBobtailDagSet::MergeDags(std::set<int16_t> &tree_ids, int16_t &new_id)
{
    RECURSIVEWRITELOCK(cs_dagset);
    int16_t base_dag_id = *(tree_ids.begin());
    // remove the first element, it is not being deleted
    tree_ids.erase(tree_ids.begin());
    for (auto &id : tree_ids)
    {
        if (id < 0 || (size_t)id >= vdags.size())
        {
            return false;
        }
        for (CDagNode* node : vdags[id]._dag)
        {
            vdags[base_dag_id].Insert(node);
        }
    }
    // before we set new ids and consume the set, use the set to update
    // compatibility for the dags
    for (auto &dag : vdags)
    {
        dag.UpdateCompatibility(base_dag_id, tree_ids);
    }
    std::priority_queue<int16_t> removed_ids;
    // erase after we move all nodes to ensure indexes still align
    // go in reverse order so indexes still align
    for (auto riter = tree_ids.rbegin(); riter != tree_ids.rend(); ++riter)
    {
        removed_ids.push(*riter);
        vdags.erase(vdags.begin() + (*riter));
    }
    SetNewIds(removed_ids);
    new_id = base_dag_id;
    return true;
}

void CBobtailDagSet::Clear()
{
    RECURSIVEWRITELOCK(cs_dagset);
    vdags.clear();
}

size_t CBobtailDagSet::Size()
{
    RECURSIVEREADLOCK(cs_dagset);
    return mapAllNodes.size();
}

bool CBobtailDagSet::Find(const uint256 &hash, CSubBlock &subblock)
{
    RECURSIVEREADLOCK(cs_dagset);
    std::map<uint256, CDagNode>::iterator iter = mapAllNodes.find(hash);
    if (iter != mapAllNodes.end())
    {
        subblock = iter->second.subblock;
        return true;
    }
    return false;
}

bool CBobtailDagSet::Contains(const uint256 &hash)
{
    return (mapAllNodes.count(hash) != 0);
}

bool CBobtailDagSet::Insert(const CSubBlock &sub_block)
{
    RECURSIVEWRITELOCK(cs_dagset);
    uint256 sub_block_hash = sub_block.GetHash();
    if (mapAllNodes.count(sub_block_hash) != 0)
    {
        // we already have this subblock in the dag
        return false;
    }

    // Create newz
    CDagNode _newNode(sub_block);
    // this emplace will always succeed since we already checked for the hash above
    auto result = mapAllNodes.emplace(_newNode.hash, _newNode);
    CDagNode *newNode = &result.first->second;

    std::set<int16_t> merge_list;
    for (auto &hash : sub_block.GetAncestorHashes())
    {
        std::map<uint256, CDagNode>::iterator ancestor_iter = mapAllNodes.find(hash);
        if (ancestor_iter == mapAllNodes.end())
        {
            // TODO : A subblock is missing, try to re-request it or something
            continue;
        }
        // use a pointer to the node already inserted in mapAllNodes to avoid obj duplication
        CDagNode* ancestor = &(ancestor_iter->second);
        newNode->AddAncestor(ancestor);
        merge_list.emplace(ancestor->dag_id);
        ancestor->AddDescendant(newNode);
    }
    int16_t new_id = -1;
    if (merge_list.size() > 1)
    {
        if (!MergeDags(merge_list, new_id))
        {
            return false;
        }
    }
    else if (merge_list.size() == 1)
    {
        new_id = *(merge_list.begin());
    }
    else // if(merge_list.size() == 0)
    {
        CreateNewDag(newNode);
        return true;
    }
    newNode->dag_id = new_id;
    if (vdags[new_id].CheckForCompatibility(newNode) == false)
    {
        return false;
    }
    vdags[new_id].Insert(newNode);
    // run compat checks for the newNode, skip the dag it belongs to,
    // we already checked this one
    for (auto &dag : vdags)
    {
        if (dag.id != new_id)
        {
            dag.CheckForCompatibility(newNode);
        }
    }
    return true;
}

void CBobtailDagSet::TemporalSort()
{

}

bool CBobtailDagSet::IsTemporallySorted()
{
    return true;
}

bool CBobtailDagSet::GetBestDag(std::set<CDagNode> &dag)
{
    RECURSIVEREADLOCK(cs_dagset);
    if (vdags.empty())
    {
        return false;
    }
    int16_t best_dag = -1;
    uint64_t best_dag_score = 0;
    // Get all dags that are big enough
    for (size_t i = 0; i < vdags.size(); ++i)
    {
        if (vdags[i]._dag.size() < BOBTAIL_K)
        {
            continue;
        }
        if (best_dag == -1)
        {
            best_dag = i;
        }
        else if (vdags[i].score > best_dag_score)
        {
            best_dag = i;
            best_dag_score = vdags[i].score;
        }
    }
    if (best_dag < 0)
    {
        // should never happen
        return false;
    }
    for (auto& node :vdags[best_dag]._dag)
    {
        dag.emplace(*node);
    }
    return true;
}

std::vector<uint256> CBobtailDagSet::GetTips()
{
    RECURSIVEREADLOCK(cs_dagset);
    std::vector<uint256> tip_hashes;
    uint64_t best_dag_score = 0;
    int16_t best_dag = -1;
    // first find the best dag, we want to mine on top of this one.
    for (auto& dag : vdags)
    {
        if (best_dag == -1)
        {
            best_dag = dag.id;
        }
        else if (dag.score > best_dag_score)
        {
            best_dag = dag.id;
            best_dag_score = dag.score;
        }
    }
    // check if we found a best dag
    if (best_dag < 0)
    {
        // if we did not then return an empty vector with no hashes
        return tip_hashes;
    }
    // if we have more than one dag we should see which dags are compatible with the best dag
    // and try to merge those dags by using the tips of all compatible dags
    std::vector<int16_t> compatible_dags;
    // the best dag is always compatible with itself so add it first
    compatible_dags.push_back(best_dag);
    if (vdags.size() > 1)
    {
        for (auto& dag : vdags)
        {
            if (dag.id != best_dag && dag.incompatible_dags.count(best_dag) == 0)
            {
                compatible_dags.push_back(dag.id);
            }
        }
    }
    // get the tips from all compatible dags
    for (auto& dag_index : compatible_dags)
    {
        for (auto &node : vdags[dag_index]._dag)
        {
            if (node->IsTip())
            {
                tip_hashes.push_back(node->hash);
            }
        }
    }
    return tip_hashes;
}
