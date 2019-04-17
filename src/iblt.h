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
#ifndef CIblt_H
#define CIblt_H

#include "serialize.h"
#include "util.h"

#include <boost/dynamic_bitset.hpp>
#include <inttypes.h>
#include <set>
#include <vector>
#include <iostream>

static const size_t VALS_32 = 4294967295;

//
// Invertible Bloom Lookup Table implementation
// References:
//
// "What's the Difference? Efficient Set Reconciliation
// without Prior Context" by Eppstein, Goodrich, Uyeda and
// Varghese
//
// "Invertible Bloom Lookup Tables" by Goodrich and
// Mitzenmacher
//

class HashTableEntry
{
public:
    int32_t count;
    uint64_t keySum;
    uint32_t keyCheck;
    std::vector<uint8_t> valueSum;

    HashTableEntry() : count(0), keySum(0), keyCheck(0) {}
    bool isPure() const;
    bool empty() const;
    void addValue(const std::vector<uint8_t> &v);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(count);
        READWRITE(keySum);
        READWRITE(keyCheck);
        READWRITE(valueSum);
    }
};

class CIblt
{
public:
    // Default constructor builds a 0 size IBLT, so is meant for two-phase construction.  Call resize() before use
    CIblt();
    CIblt(uint64_t version);
    // Pass the expected number of entries in the IBLT table. If the number of entries exceeds
    // the expected, then the decode failure rate will increase dramatically.
    CIblt(size_t _expectedNumEntries, uint64_t _version);
    // The salt value is used to create a distinct hash seed for each hash function.
    CIblt(size_t _expectedNumEntries, uint32_t salt, uint64_t _version);
    // Copy constructor
    CIblt(const CIblt &other);
    ~CIblt();

    // Clears all entries in the IBLT
    void reset();
    // Returns the size in bytes of the IBLT.  This is NOT the count of inserted entries
    uint64_t size();
    void resize(size_t _expectedNumEntries);
    uint32_t saltedHashValue(size_t hashFuncIdx, const std::vector<uint8_t> &kvec) const;
    void insert(uint64_t k, const std::vector<uint8_t> &v);
    void erase(uint64_t k, const std::vector<uint8_t> &v);

    // Returns true if a result is definitely found or not
    // found. If not found, result will be empty.
    // Returns false if overloaded and we don't know whether or
    // not k is in the table.
    bool get(uint64_t k, std::vector<uint8_t> &result) const;

    // Adds entries to the given sets:
    //  positive is all entries that were inserted
    //  negative is all entreis that were erased but never added (or
    //   if the IBLT = A-B, all entries in B that are not in A)
    // Returns true if all entries could be decoded, false otherwise.
    bool listEntries(std::set<std::pair<uint64_t, std::vector<uint8_t> > > &positive,
        std::set<std::pair<uint64_t, std::vector<uint8_t> > > &negative) const;

    // Subtract two IBLTs
    CIblt operator-(const CIblt &other) const;

    // Returns the optimal number of hash buckets for a certain number of entries
    static size_t OptimalNHash(size_t expectedNumEntries);
    // Returns the optimal ratio of memory cells to expected entries.
    // OptimalOverhead()*expectedNumEntries <= allocated memory cells
    static float OptimalOverhead(size_t expectedNumEntries);
    // Returns the maximum number of hash functions for any number of entries.
    static uint8_t MaxNHash();

    // For debugging:
    std::string DumpTable() const;
    uint8_t getNHash() { return n_hash; }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(COMPACTSIZE(version));

        if (version > 0)
        {
            READWRITE(mapHashIdxSeeds);
            READWRITE(salt);
        }

        if (ser_action.ForRead() && version > 1){
            LOG(GRAPHENE, "VERSION ERROR IN IBLT: %d\n", version);
            throw std::ios_base::failure("No IBLT version exceeding 1 is currently known.");
        }

        READWRITE(n_hash);
        if (ser_action.ForRead() && n_hash == 0)
        {
            throw std::ios_base::failure("CIblt Number of IBLT hash functions needs to be > 0");
        }
        READWRITE(is_modified);
        READWRITE(hashTable);
    }

    // Returns true if any elements have been inserted into the IBLT since creation or reset
    inline bool isModified() { return is_modified; }
protected:
    void _insert(int plusOrMinus, uint64_t k, const std::vector<uint8_t> &v);

    // This salt is used to seed the IBLT hash functions. When its value (passed in via constructor)
    // is derived from a pseudo-random value, the IBLT hash functions themselves become randomized.
    uint32_t salt;
    uint64_t version;
    uint8_t n_hash;
    bool is_modified;

    std::vector<HashTableEntry> hashTable;
    std::map<uint8_t, uint32_t> mapHashIdxSeeds;
};

// Beginning at version 2 and higher, new features will be added to the implementations
// of HashTableEntry and CIblt defined below. The reason for the split is the removal of
// the keyCheck field from HashTableEntry, which cannot be retrofitted to the old implementation.

class HashTableEntryNoCheck
{
public:
    int32_t count;
    uint64_t keySum;
    std::vector<uint8_t> valueSum;

    HashTableEntryNoCheck() : count(0), keySum(0) {}
    bool isPure(uint32_t checksum, uint32_t checksumSpace) const;
    bool empty(uint32_t checksum) const;
    void addValue(const std::vector<uint8_t> &v);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(count);
        READWRITE(keySum);
        READWRITE(valueSum);
    }
};

class CIbltNoCheck
{
public:
    // Default constructor builds a 0 size IBLT, so is meant for two-phase construction.  Call resize() before use
    CIbltNoCheck();
    CIbltNoCheck(uint64_t _version);
    // Pass the expected number of entries in the IBLT table. If the number of entries exceeds
    // the expected, then the decode failure rate will increase dramatically.
    CIbltNoCheck(size_t _expectedNumEntries, uint64_t _version);
    // The salt value is used to create a distinct hash seed for each hash function.
    CIbltNoCheck(size_t _expectedNumEntries, uint32_t salt, uint64_t _version);
    // nChecksumBits checksum bits will be used per cell for the purpose of detecting garbage contents
    CIbltNoCheck(size_t _expectedNumEntries, uint32_t salt, uint64_t _version, uint8_t _nChecksumBits);
    // Copy constructor
    CIbltNoCheck(const CIbltNoCheck &other);
    ~CIbltNoCheck();

    // Clears all entries in the IBLT
    void reset();
    // Returns the size in bytes of the IBLT.  This is NOT the count of inserted entries
    uint64_t size();
    void resize(size_t _expectedNumEntries);
    uint32_t saltedHashValue(size_t hashFuncIdx, const std::vector<uint8_t> &kvec) const;
    void insert(uint64_t k, const std::vector<uint8_t> &v);
    void erase(uint64_t k, const std::vector<uint8_t> &v);

    // Returns true if a result is definitely found or not
    // found. If not found, result will be empty.
    // Returns false if overloaded and we don't know whether or
    // not k is in the table.
    bool get(uint64_t k, std::vector<uint8_t> &result) const;

    // Adds entries to the given sets:
    //  positive is all entries that were inserted
    //  negative is all entreis that were erased but never added (or
    //   if the IBLT = A-B, all entries in B that are not in A)
    // Returns true if all entries could be decoded, false otherwise.
    bool listEntries(std::set<std::pair<uint64_t, std::vector<uint8_t> > > &positive,
        std::set<std::pair<uint64_t, std::vector<uint8_t> > > &negative) const;

    // Subtract two IBLTs
    CIbltNoCheck operator-(const CIbltNoCheck &other) const;

    // Read checksum for cell "entry" from the global checksum bit array
    uint32_t readChecksum(size_t entryIdx) const;
    // Write checksum for cell "entry" to the global checksum bit array
    void writeChecksum(size_t entryIdx, uint32_t checksum);

    // Returns the optimal number of hash buckets for a certain number of entries
    static size_t OptimalNHash(size_t expectedNumEntries);
    // Returns the optimal ratio of memory cells to expected entries.
    // OptimalOverhead()*expectedNumEntries <= allocated memory cells
    static float OptimalOverhead(size_t expectedNumEntries);
    // Returns the maximum number of hash functions for any number of entries.
    static uint8_t MaxNHash();

    // For debugging:
    std::string DumpTable() const;
    uint8_t getNHash() { return n_hash; }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(COMPACTSIZE(version));

        if (version > 0)
        {
            READWRITE(mapHashIdxSeeds);
            READWRITE(salt);
        }

        if (ser_action.ForRead() && version > 2)
            throw std::ios_base::failure("No IBLT version exceeding 2 is currently known.");

        READWRITE(n_hash);
        if (ser_action.ForRead() && n_hash == 0)
        {
            throw std::ios_base::failure("Number of IBLT hash functions needs to be > 0");
        }
        READWRITE(is_modified);
        READWRITE(hashTable);

        READWRITE(nChecksumBits);
        if (!ser_action.ForRead()) 
        {
            vChecksumBlocks.resize(vChecksums.num_blocks());
            boost::to_block_range(vChecksums, vChecksumBlocks.begin());
        }
        READWRITE(vChecksumBlocks);
        if (ser_action.ForRead()) 
        {
            vChecksums.resize(8 * vChecksumBlocks.size());
            boost::from_block_range(vChecksumBlocks.begin(), vChecksumBlocks.end(), vChecksums);
        }
    }

    // Returns true if any elements have been inserted into the IBLT since creation or reset
    inline bool isModified() { return is_modified; }
protected:
    void _insert(int plusOrMinus, uint64_t k, const std::vector<uint8_t> &v);

    // This salt is used to seed the IBLT hash functions. When its value (passed in via constructor)
    // is derived from a pseudo-random value, the IBLT hash functions themselves become randomized.
    uint8_t nChecksumBits;
    // This member holds the checksum bits for all cells, but it is never serialized
    boost::dynamic_bitset<uint8_t, std::allocator<uint8_t>> vChecksums;
    // This member holds the compressed contents of vChecksums; it is used for serialization / deserialization
    std::vector<uint8_t> vChecksumBlocks;
    uint32_t salt;
    uint64_t version;
    uint8_t n_hash;
    bool is_modified;

    std::vector<HashTableEntryNoCheck> hashTable;
    std::map<uint8_t, uint32_t> mapHashIdxSeeds;
};

#endif /* CIblt_H */
