#include "bobtail/bobtail.h"
#include "bobtail/dag.h"
#include "bobtail/subblock.h"
#include "test/test_bitcoin.h"
#include <boost/math/distributions/gamma.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bobtail_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_dag_temporal_sort)
{
    CBobtailDagSet forest;
    CSubBlock subblock1;
    CSubBlock subblock2;
    forest.Insert(subblock1);
    forest.Insert(subblock2);
    forest.TemporalSort();

    BOOST_CHECK(forest.IsTemporallySorted());
}

BOOST_AUTO_TEST_CASE(test_dag_score)
{
    /* n1 -> n2
     *  |
     *  ---> n3 -> n4
     *  Scores:
     *      n4: 1
     *      n3: 1+ 2*1 = 3
     *      n2: 1
     *      n1: 1 + 3*(3+1) = 13
     */
    int anticipatedTotalScore = 18;
    // root node
    CSubBlock subblock1;
    CDagNode *node1 = new CDagNode(subblock1);
    // two descendants, which are siblings
    CSubBlock subblock2;
    CDagNode *node2 = new CDagNode(subblock2);
    node1->AddDescendant(node2);
    node2->AddAncestor(node1);
    CSubBlock subblock3;
    CDagNode *node3 = new CDagNode(subblock3);
    node1->AddDescendant(node3);
    node3->AddAncestor(node1);
    // one descendant, which is child of one sibling
    CSubBlock subblock4;
    CDagNode *node4 = new CDagNode(subblock4);
    node3->AddDescendant(node4);
    node4->AddAncestor(node3);

    // create dag
    CBobtailDag dag(0, node1);
    dag.Insert(node2);
    dag.Insert(node3);
    dag.Insert(node4);

    BOOST_CHECK(dag.score == anticipatedTotalScore);
}

BOOST_AUTO_TEST_CASE(arith_uint256_sanity)
{
    unsigned int nBits = 545259519;
    arith_uint256 a;
    a.SetCompact(nBits);
    arith_uint256 b;
    b.SetCompact(nBits);
    b /= 1000;
    arith_uint256 c;
    a.SetCompact(nBits);
    c = ~c;
    c *= 1000;
    c = ~c;

    BOOST_CHECK(a > b);
    BOOST_CHECK(a > c);
}

BOOST_AUTO_TEST_CASE(gamma_sanity_check)
{
    // The median of the exponential distribution with mean 1 should be ln(2)
    boost::math::gamma_distribution<> expon(1,1);
    BOOST_CHECK(quantile(expon, 0.5) == std::log(2));

    // The quantile of the density of a gamma at its mean should be equal to k*scale_parameter 
    uint8_t k = 3;
    arith_uint256 scale = arith_uint256(1e6);
    boost::math::gamma_distribution<> bobtail_gamma(k, scale.getdouble());
    BOOST_CHECK(quantile(bobtail_gamma, cdf(bobtail_gamma, mean(bobtail_gamma))) == k*scale.getdouble());
}

BOOST_AUTO_TEST_CASE(test_scaling_gamma, *boost::unit_test::tolerance(0.000001))
{
    uint8_t k = 3;
    arith_uint256 scale = arith_uint256(1e6);
    arith_uint256 scaler = arith_uint256(13);
    arith_uint256 scaled_scale = scale / scaler;
    boost::math::gamma_distribution<> bobtail_gamma(k, scale.getdouble());
    boost::math::gamma_distribution<> bobtail_gamma_scaled(k, scaled_scale.getdouble());

    double mean1 = mean(bobtail_gamma);
    double mean2 = scaler.getdouble()*mean(bobtail_gamma_scaled);
    double relative_error = std::abs(mean1 - mean2) / mean1;
}

BOOST_AUTO_TEST_CASE(test_kos_threshold)
{
    uint8_t k = 3;
    arith_uint256 target(1e6);

    double thresh = GetKOSThreshold(target, k);
    // Threshold should be larger than mean
    BOOST_CHECK(thresh > target.getdouble()*k);
}

BOOST_AUTO_TEST_CASE(test_is_below_kos_threshold)
{
    uint8_t k = 3;
    arith_uint256 target(1e6);
    arith_uint256 lowPow(k*1e5);
    arith_uint256 highPow(k*1e7);

    // the first two tests do not use scaling
    // low pow should pass
    BOOST_CHECK(IsBelowKOSThreshold(lowPow, target, k, (int)target.getdouble()));
    // high pow should fail
    BOOST_CHECK(!IsBelowKOSThreshold(highPow, target, k, (int)target.getdouble()));

    // now check with default scaling
    BOOST_CHECK(IsBelowKOSThreshold(lowPow, target, k));
    BOOST_CHECK(!IsBelowKOSThreshold(highPow, target, k));
}

BOOST_AUTO_TEST_CASE(test_best_k)
{
    uint16_t desiredDagNodes = 30;
    double probability = 0.9;

    uint32_t k = GetBestK(desiredDagNodes, probability);

    // wolfram alpha 90th percentile from query: "gamma quantile shape=23 scale=1 "
    BOOST_CHECK(k == 23);
}

BOOST_AUTO_TEST_SUITE_END()
