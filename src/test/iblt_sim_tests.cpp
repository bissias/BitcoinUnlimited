#include <boost/test/unit_test.hpp>
#include <cassert>
#include <iostream>

#include "hash.h"
#include "iblt.h"
#include "test/test_bitcoin.h"
#include "utilstrencodings.h"

const std::vector<uint8_t> IBLT_NULL_VALUE = {};

std::vector<uint8_t> RandomValue(uint32_t n)
{
    std::vector<uint8_t> result;
    for (int i = 0; i < 4; i++)
    {
        result.push_back(static_cast<uint8_t>(MurmurHash3(n + i, result) & 0xff));
    }
    return result;
}

BOOST_FIXTURE_TEST_SUITE(iblt_sim_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(iblt_concatenation)
{
    uint64_t trials = 100000;
    size_t nItemList[] = {10, 50, 500, 5000};

    for (size_t nItems : nItemList)
    {
        std::set<std::pair<uint64_t, std::vector<uint8_t> > > entries;
        uint64_t singleSuccesses = 0;
        uint64_t doubleSuccesses = 0;
        for (int trial=0;trial < trials;trial++)
        {
            CIblt t1(nItems, 1);
            for (int i = 0; i < nItems; i++)
                t1.insert(trial + i*trials, RandomValue(i));

            singleSuccesses += t1.listEntries(entries, entries);

            CIblt t2(nItems, 2);
            for (int i = 0; i < nItems; i++)
                t2.insert(trial + i*trials, RandomValue(i));

            t1.concat(t2);

            doubleSuccesses += t1.listEntries(entries, entries);
        }

        std::cout<<"nItems: "<<nItems<<"single successes: "<<singleSuccesses<<" double success: "<<doubleSuccesses<<std::endl;
    }
}

BOOST_AUTO_TEST_SUITE_END()
