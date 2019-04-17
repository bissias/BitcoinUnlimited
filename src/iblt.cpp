/*
Copyright (c) 2018 The Bitcoin Unlimited developers
Copyright (c) 2014 Gavin Andresen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#include "iblt.h"
#include "hash.h"
#include "iblt_params.h"
#include <cassert>
#include <iostream>
#include <list>
#include <sstream>
#include <utility>

static const size_t N_HASHCHECK = 11;
// It's extremely unlikely that an IBLT will decode with fewer
// than 1 cell for every 10 items.
static const float MIN_OVERHEAD = 0.1;

// mask that can be reduced to reduce the number of checksum bits in the IBLT
// -- ANY VALUE OTHER THAN 0xffffffff IS FOR TESTING ONLY! --
static const uint32_t KEYCHECK_MASK = 0xffffffff;

static inline uint32_t keyChecksumCalc(const std::vector<uint8_t> &kvec)
{
    return MurmurHash3(N_HASHCHECK, kvec) & KEYCHECK_MASK;
}


template <typename T>
std::vector<uint8_t> ToVec(T number)
{
    std::vector<uint8_t> v(sizeof(T));
    for (size_t i = 0; i < sizeof(T); i++)
    {
        v.at(i) = (number >> i * 8) & 0xff;
    }
    return v;
}


bool HashTableEntry::isPure() const
{
    if (count == 1 || count == -1)
    {
        uint32_t check = keyChecksumCalc(ToVec(keySum));
        return (keyCheck == check);
    }
    return false;
}

bool HashTableEntry::empty() const { return (count == 0 && keySum == 0 && keyCheck == 0); }
void HashTableEntry::addValue(const std::vector<uint8_t> &v)
{
    if (v.empty())
    {
        return;
    }
    if (valueSum.size() < v.size())
    {
        valueSum.resize(v.size());
    }
    for (size_t i = 0; i < v.size(); i++)
    {
        valueSum[i] ^= v[i];
    }
}

CIblt::CIblt()
{
    salt = 0;
    n_hash = 1;
    is_modified = false;
    version = 0;
}

CIblt::CIblt(uint64_t _version)
{
    salt = 0;
    n_hash = 1;
    is_modified = false;

    CIblt::version = _version;
}

CIblt::CIblt(size_t _expectedNumEntries, uint64_t _version) : n_hash(0), is_modified(false), salt(0)
{
    CIblt::version = _version;
    CIblt::resize(_expectedNumEntries);
}

CIblt::CIblt(size_t _expectedNumEntries, uint32_t _salt, uint64_t _version) : n_hash(0), is_modified(false)
{
    CIblt::version = _version;
    CIblt::salt = _salt;
    CIblt::resize(_expectedNumEntries);
}

CIblt::CIblt(const CIblt &other) : n_hash(0), is_modified(false)
{
    salt = other.salt;
    version = other.version;
    n_hash = other.n_hash;
    hashTable = other.hashTable;
    mapHashIdxSeeds = other.mapHashIdxSeeds;
}

CIblt::~CIblt() {}
void CIblt::reset()
{
    size_t size = this->size();
    hashTable.clear();
    hashTable.resize(size);
    is_modified = false;
}

uint64_t CIblt::size() { return hashTable.size(); }
void CIblt::resize(size_t _expectedNumEntries)
{
    assert(is_modified == false);

    CIblt::n_hash = OptimalNHash(_expectedNumEntries);

    // set hash seeds from salt
    for (size_t i = 0; i < n_hash; i++)
        mapHashIdxSeeds[i] = salt % (0xffffffff - n_hash) + i;

    // reduce probability of failure by increasing by overhead factor
    size_t nEntries = (size_t)(_expectedNumEntries * OptimalOverhead(_expectedNumEntries));
    // ... make nEntries exactly divisible by n_hash
    while (n_hash * (nEntries / n_hash) != nEntries)
        ++nEntries;
    hashTable.resize(nEntries);
}

uint32_t CIblt::saltedHashValue(size_t hashFuncIdx, const std::vector<uint8_t> &kvec) const
{
    if (version > 0)
    {
        uint32_t seed = mapHashIdxSeeds.at(hashFuncIdx);
        return MurmurHash3(seed, kvec);
    }
    else
        return MurmurHash3(hashFuncIdx, kvec);
}

void CIblt::_insert(int plusOrMinus, uint64_t k, const std::vector<uint8_t> &v)
{
    if (!n_hash)
        return;
    size_t bucketsPerHash = hashTable.size() / n_hash;
    if (!bucketsPerHash)
        return;

    std::vector<uint8_t> kvec = ToVec(k);
    const uint32_t kchk = keyChecksumCalc(kvec);

    for (size_t i = 0; i < n_hash; i++)
    {
        size_t startEntry = i * bucketsPerHash;

        uint32_t h = saltedHashValue(i, kvec);
        HashTableEntry &entry = hashTable.at(startEntry + (h % bucketsPerHash));
        entry.count += plusOrMinus;
        entry.keySum ^= k;
        entry.keyCheck ^= kchk;
        if (entry.empty())
        {
            entry.valueSum.clear();
        }
        else
        {
            entry.addValue(v);
        }
    }

    is_modified = true;
}

void CIblt::insert(uint64_t k, const std::vector<uint8_t> &v) { _insert(1, k, v); }
void CIblt::erase(uint64_t k, const std::vector<uint8_t> &v) { _insert(-1, k, v); }
bool CIblt::get(uint64_t k, std::vector<uint8_t> &result) const
{
    result.clear();


    if (!n_hash)
        return false;
    size_t bucketsPerHash = hashTable.size() / n_hash;
    if (!bucketsPerHash)
        return false;

    std::vector<uint8_t> kvec = ToVec(k);

    for (size_t i = 0; i < n_hash; i++)
    {
        size_t startEntry = i * bucketsPerHash;

        uint32_t h = saltedHashValue(i, kvec);
        const HashTableEntry &entry = hashTable.at(startEntry + (h % bucketsPerHash));

        if (entry.empty())
        {
            // Definitely not in table. Leave
            // result empty, return true.
            return true;
        }
        else if (entry.isPure())
        {
            if (entry.keySum == k)
            {
                // Found!
                result.assign(entry.valueSum.begin(), entry.valueSum.end());
                return true;
            }
            else
            {
                // Definitely not in table.
                return true;
            }
        }
    }

    // Don't know if k is in table or not; "peel" the IBLT to try to find
    // it:
    CIblt peeled = *this;
    size_t nErased = 0;
    for (size_t i = 0; i < peeled.hashTable.size(); i++)
    {
        HashTableEntry &entry = peeled.hashTable.at(i);
        if (entry.isPure())
        {
            if (entry.keySum == k)
            {
                // Found!
                result.assign(entry.valueSum.begin(), entry.valueSum.end());
                return true;
            }
            ++nErased;
            // NOTE: Need to create a copy of valueSum here as entry is just a reference!
            std::vector<uint8_t> vec = entry.valueSum;
            peeled._insert(-entry.count, entry.keySum, vec);
        }
    }
    if (nErased > 0)
    {
        // Recurse with smaller IBLT
        return peeled.get(k, result);
    }
    return false;
}

bool CIblt::listEntries(std::set<std::pair<uint64_t, std::vector<uint8_t> > > &positive,
    std::set<std::pair<uint64_t, std::vector<uint8_t> > > &negative) const
{
    CIblt peeled = *this;

    size_t nErased = 0;
    size_t nTotalErased = 0;
    do
    {
        nErased = 0;
        for (size_t i = 0; i < peeled.hashTable.size(); i++)
        {
            HashTableEntry &entry = peeled.hashTable.at(i);
            if (entry.isPure())
            {
                if (entry.count == 1)
                {
                    positive.insert(std::make_pair(entry.keySum, entry.valueSum));
                }
                else
                {
                    negative.insert(std::make_pair(entry.keySum, entry.valueSum));
                }
                // NOTE: Need to create a copy of valueSum here as entry is just a reference!
                std::vector<uint8_t> vec = entry.valueSum;
                peeled._insert(-entry.count, entry.keySum, vec);
                ++nErased;
            }
        }
        nTotalErased += nErased;
    } while (nErased > 0 && nTotalErased < peeled.hashTable.size() / MIN_OVERHEAD);

    if (!n_hash)
        return false;
    size_t peeled_bucketsPerHash = peeled.hashTable.size() / n_hash;
    if (!peeled_bucketsPerHash)
        return false;

    // If any buckets for one of the hash functions is not empty,
    // then we didn't peel them all:
    for (size_t i = 0; i < peeled_bucketsPerHash; i++)
    {
        if (peeled.hashTable.at(i).empty() != true)
            return false;
    }
    return true;
}

CIblt CIblt::operator-(const CIblt &other) const
{
    // IBLT's must be same params/size:
    assert(hashTable.size() == other.hashTable.size());

    CIblt result(*this);
    for (size_t i = 0; i < hashTable.size(); i++)
    {
        HashTableEntry &e1 = result.hashTable.at(i);
        const HashTableEntry &e2 = other.hashTable.at(i);
        e1.count -= e2.count;
        e1.keySum ^= e2.keySum;
        e1.keyCheck ^= e2.keyCheck;
        if (e1.empty())
        {
            e1.valueSum.clear();
        }
        else
        {
            e1.addValue(e2.valueSum);
        }
    }

    return result;
}

// For debugging during development:
std::string CIblt::DumpTable() const
{
    std::ostringstream result;

    result << "count keySum keyCheckMatch\n";
    for (size_t i = 0; i < hashTable.size(); i++)
    {
        const HashTableEntry &entry = hashTable.at(i);
        result << entry.count << " " << entry.keySum << " ";
        result << (keyChecksumCalc(ToVec(entry.keySum)) == entry.keyCheck ? "true" : "false");
        result << "\n";
    }

    return result.str();
}

size_t CIblt::OptimalNHash(size_t expectedNumEntries) { return CIbltParams::Lookup(expectedNumEntries).numhashes; }
float CIblt::OptimalOverhead(size_t expectedNumEntries) { return CIbltParams::Lookup(expectedNumEntries).overhead; }
uint8_t CIblt::MaxNHash()
{
    uint8_t maxHashes = 4;

    for (auto &pair : CIbltParams::paramMap)
    {
        if (pair.second.numhashes > maxHashes)
            maxHashes = pair.second.numhashes;
    }

    return maxHashes;
}


/******** version > 1 *********/


static inline uint32_t keyChecksumCalcNoCheck(const std::vector<uint8_t> &kvec, uint32_t checksumSpace)
{
    return MurmurHash3(N_HASHCHECK, kvec) % checksumSpace;
}

bool HashTableEntryNoCheck::isPure(uint32_t checksum, uint32_t checksumSpace) const
{
    if (count == 1 || count == -1)
    {
        uint32_t check = keyChecksumCalcNoCheck(ToVec(keySum), checksumSpace);
        return (checksum == check);
    }
    return false;
}

bool HashTableEntryNoCheck::empty(uint32_t checksum) const { 
    return (count == 0 && keySum == 0 && checksum == 0); 
}

void HashTableEntryNoCheck::addValue(const std::vector<uint8_t> &v)
{
    if (v.empty())
    {
        return;
    }
    if (valueSum.size() < v.size())
    {
        valueSum.resize(v.size());
    }
    for (size_t i = 0; i < v.size(); i++)
    {
        valueSum[i] ^= v[i];
    }
}

CIbltNoCheck::CIbltNoCheck()
{
    salt = 0;
    n_hash = 1;
    is_modified = false;
    version = 2;
    nChecksumBits = 32;
}

CIbltNoCheck::CIbltNoCheck(uint64_t _version)
{
    salt = 0;
    n_hash = 1;
    is_modified = false;
    nChecksumBits = 32;

    CIbltNoCheck::version = _version;

    if (CIbltNoCheck::version < 2)
        throw std::ios_base::failure("CIbltNoCheck version must exceed version 1");
}

CIbltNoCheck::CIbltNoCheck(size_t _expectedNumEntries, uint64_t _version) : n_hash(0), is_modified(false), salt(0), nChecksumBits(32)
{
    CIbltNoCheck::version = _version;
    CIbltNoCheck::resize(_expectedNumEntries);

    if (CIbltNoCheck::version < 2)
        throw std::ios_base::failure("CIbltNoCheck version must exceed version 1");
}

CIbltNoCheck::CIbltNoCheck(size_t _expectedNumEntries, uint32_t _salt, uint64_t _version) : n_hash(0), is_modified(false), nChecksumBits(32)
{
    CIbltNoCheck::version = _version;
    CIbltNoCheck::salt = _salt;
    CIbltNoCheck::resize(_expectedNumEntries);

    if (CIbltNoCheck::version < 2)
        throw std::ios_base::failure("CIbltNoCheck version must exceed version 1");
}

CIbltNoCheck::CIbltNoCheck(size_t _expectedNumEntries, uint32_t _salt, uint64_t _version, uint8_t _nChecksumBits) : n_hash(0), is_modified(false)
{
    CIbltNoCheck::version = _version;
    CIbltNoCheck::salt = _salt;
    CIbltNoCheck::nChecksumBits = _nChecksumBits;
    CIbltNoCheck::resize(_expectedNumEntries);

    if (CIbltNoCheck::version < 2)
        throw std::ios_base::failure("CIbltNoCheck version must exceed version 1");
}

CIbltNoCheck::CIbltNoCheck(const CIbltNoCheck &other) : n_hash(0), is_modified(false)
{
    salt = other.salt;
    version = other.version;
    n_hash = other.n_hash;
    hashTable = other.hashTable;
    nChecksumBits = other.nChecksumBits;
    vChecksums = other.vChecksums;
    mapHashIdxSeeds = other.mapHashIdxSeeds;

    if (version < 2)
        throw std::ios_base::failure("CIbltNoCheck version must exceed version 1");
}

CIbltNoCheck::~CIbltNoCheck() {}
void CIbltNoCheck::reset()
{
    size_t size = this->size();
    hashTable.clear();
    hashTable.resize(size);
    vChecksums.clear();
    vChecksums.resize(nChecksumBits*size, false);
    is_modified = false;
}

uint64_t CIbltNoCheck::size() { return hashTable.size(); }
void CIbltNoCheck::resize(size_t _expectedNumEntries)
{
    assert(is_modified == false);

    CIbltNoCheck::n_hash = OptimalNHash(_expectedNumEntries);

    // set hash seeds from salt
    for (size_t i = 0; i < n_hash; i++)
        mapHashIdxSeeds[i] = salt % (0xffffffff - n_hash) + i;

    // reduce probability of failure by increasing by overhead factor
    size_t nEntries = (size_t)(_expectedNumEntries * OptimalOverhead(_expectedNumEntries));
    // ... make nEntries exactly divisible by n_hash
    while (n_hash * (nEntries / n_hash) != nEntries)
        ++nEntries;
    hashTable.resize(nEntries);

    vChecksums.resize(nEntries * nChecksumBits, false);
}

uint32_t CIbltNoCheck::saltedHashValue(size_t hashFuncIdx, const std::vector<uint8_t> &kvec) const
{
    if (version > 0)
    {
        uint32_t seed = mapHashIdxSeeds.at(hashFuncIdx);
        return MurmurHash3(seed, kvec);
    }
    else
        return MurmurHash3(hashFuncIdx, kvec);
}

void CIbltNoCheck::_insert(int plusOrMinus, uint64_t k, const std::vector<uint8_t> &v)
{
    if (!n_hash)
        return;
    size_t bucketsPerHash = hashTable.size() / n_hash;
    if (!bucketsPerHash)
        return;

    std::vector<uint8_t> kvec = ToVec(k);
    uint32_t checksumSpace = (int) std::pow(2, nChecksumBits);
    const uint32_t kchk = keyChecksumCalcNoCheck(kvec, checksumSpace);

    for (size_t i = 0; i < n_hash; i++)
    {
        size_t startEntry = i * bucketsPerHash;

        uint32_t h = saltedHashValue(i, kvec);
        size_t entryIdx = startEntry + (h % bucketsPerHash);
        HashTableEntryNoCheck &entry = hashTable.at(entryIdx);
        entry.count += plusOrMinus;
        entry.keySum ^= k;
        uint32_t checksum = readChecksum(entryIdx);
        checksum ^= kchk;
        writeChecksum(entryIdx, checksum);
        if (entry.empty(checksum))
        {
            entry.valueSum.clear();
        }
        else
        {
            entry.addValue(v);
        }
    }

    is_modified = true;
}

void CIbltNoCheck::insert(uint64_t k, const std::vector<uint8_t> &v) { _insert(1, k, v); }
void CIbltNoCheck::erase(uint64_t k, const std::vector<uint8_t> &v) { _insert(-1, k, v); }
bool CIbltNoCheck::get(uint64_t k, std::vector<uint8_t> &result) const
{
    result.clear();
    uint32_t checksumSpace = (int) std::pow(2, nChecksumBits);

    if (!n_hash)
        return false;
    size_t bucketsPerHash = hashTable.size() / n_hash;
    if (!bucketsPerHash)
        return false;

    std::vector<uint8_t> kvec = ToVec(k);

    for (size_t i = 0; i < n_hash; i++)
    {
        size_t startEntry = i * bucketsPerHash;

        uint32_t h = saltedHashValue(i, kvec);
        size_t entryIdx = startEntry + (h % bucketsPerHash);
        const HashTableEntryNoCheck &entry = hashTable.at(entryIdx);
        uint32_t checksum = readChecksum(entryIdx);

        if (entry.empty(checksum))
        {
            // Definitely not in table. Leave
            // result empty, return true.
            return true;
        }
        else if (entry.isPure(checksum, checksumSpace))
        {
            if (entry.keySum == k)
            {
                // Found!
                result.assign(entry.valueSum.begin(), entry.valueSum.end());
                return true;
            }
            else
            {
                // Definitely not in table.
                return true;
            }
        }
    }

    // Don't know if k is in table or not; "peel" the IBLT to try to find
    // it:
    CIbltNoCheck peeled = *this;
    size_t nErased = 0;
    for (size_t i = 0; i < peeled.hashTable.size(); i++)
    {
        HashTableEntryNoCheck &entry = peeled.hashTable.at(i);
        uint32_t checksum = readChecksum(i);
        if (entry.isPure(checksum, checksumSpace))
        {
            if (entry.keySum == k)
            {
                // Found!
                result.assign(entry.valueSum.begin(), entry.valueSum.end());
                return true;
            }
            ++nErased;
            // NOTE: Need to create a copy of valueSum here as entry is just a reference!
            std::vector<uint8_t> vec = entry.valueSum;
            peeled._insert(-entry.count, entry.keySum, vec);
        }
    }
    if (nErased > 0)
    {
        // Recurse with smaller IBLT
        return peeled.get(k, result);
    }
    return false;
}

bool CIbltNoCheck::listEntries(std::set<std::pair<uint64_t, std::vector<uint8_t> > > &positive,
    std::set<std::pair<uint64_t, std::vector<uint8_t> > > &negative) const
{
    CIbltNoCheck peeled = *this;
    uint32_t checksumSpace = (int) std::pow(2, nChecksumBits);

    size_t nErased = 0;
    size_t nTotalErased = 0;
    do
    {
        nErased = 0;
        for (size_t i = 0; i < peeled.hashTable.size(); i++)
        {
            HashTableEntryNoCheck &entry = peeled.hashTable.at(i);
            uint32_t checksum = peeled.readChecksum(i);
            if (entry.isPure(checksum, checksumSpace))
            {
                if (entry.count == 1)
                {
                    positive.insert(std::make_pair(entry.keySum, entry.valueSum));
                }
                else
                {
                    negative.insert(std::make_pair(entry.keySum, entry.valueSum));
                }
                // NOTE: Need to create a copy of valueSum here as entry is just a reference!
                std::vector<uint8_t> vec = entry.valueSum;
                peeled._insert(-entry.count, entry.keySum, vec);
                ++nErased;
            }
        }
        nTotalErased += nErased;
    } while (nErased > 0 && nTotalErased < peeled.hashTable.size() / MIN_OVERHEAD);

    if (!n_hash)
        return false;
    size_t peeled_bucketsPerHash = peeled.hashTable.size() / n_hash;
    if (!peeled_bucketsPerHash)
        return false;

    // If any buckets for one of the hash functions is not empty,
    // then we didn't peel them all:
    for (size_t i = 0; i < peeled_bucketsPerHash; i++)
    {
        uint32_t checksum = peeled.readChecksum(i);
        if (peeled.hashTable.at(i).empty(checksum) != true)
            return false;
    }
    return true;
}

CIbltNoCheck CIbltNoCheck::operator-(const CIbltNoCheck &other) const
{
    // IBLT's must be same params/size:
    assert(hashTable.size() == other.hashTable.size());

    CIbltNoCheck result(*this);
    for (size_t i = 0; i < hashTable.size(); i++)
    {
        HashTableEntryNoCheck &e1 = result.hashTable.at(i);
        const HashTableEntryNoCheck &e2 = other.hashTable.at(i);
        e1.count -= e2.count;
        e1.keySum ^= e2.keySum;
        uint32_t checksum = result.readChecksum(i);
        checksum ^= other.readChecksum(i);
        result.writeChecksum(i, checksum);
        if (e1.empty(checksum))
        {
            e1.valueSum.clear();
        }
        else
        {
            e1.addValue(e2.valueSum);
        }
    }

    return result;
}

uint32_t CIbltNoCheck::readChecksum(size_t entryIdx) const {
    uint32_t checksum = 0;

    for (int i=0;i < nChecksumBits;i++)
    {
        checksum += vChecksums[i + entryIdx*nChecksumBits] << i; 
    }

    return checksum;
}

void CIbltNoCheck::writeChecksum(size_t entryIdx, uint32_t checksum) {
    for (int i=0;i < nChecksumBits;i++)
    {
        vChecksums[i + entryIdx*nChecksumBits] = (checksum >> i) % 2;
    }
}

// For debugging during development:
std::string CIbltNoCheck::DumpTable() const
{
    std::ostringstream result;

    result << "count keySum keyCheckMatch\n";
    for (size_t i = 0; i < hashTable.size(); i++)
    {
        const HashTableEntryNoCheck &entry = hashTable.at(i);
        result << entry.count << " " << entry.keySum << " ";
        uint32_t keyCheck = readChecksum(i);
        result << (keyChecksumCalcNoCheck(ToVec(entry.keySum), nChecksumBits) == keyCheck ? "true" : "false");
        result << "\n";
    }

    return result.str();
}

size_t CIbltNoCheck::OptimalNHash(size_t expectedNumEntries) { return CIbltParams::Lookup(expectedNumEntries).numhashes; }
float CIbltNoCheck::OptimalOverhead(size_t expectedNumEntries) { return CIbltParams::Lookup(expectedNumEntries).overhead; }
uint8_t CIbltNoCheck::MaxNHash()
{
    uint8_t maxHashes = 4;

    for (auto &pair : CIbltParams::paramMap)
    {
        if (pair.second.numhashes > maxHashes)
            maxHashes = pair.second.numhashes;
    }

    return maxHashes;
}
