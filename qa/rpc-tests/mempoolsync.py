#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import time


class MempoolSyncTest(BitcoinTestFramework):
    expected_stats = {'enabled', 
                      'filter', 
                      'graphene_additional_tx_size', 
                      'graphene_block_size', 
                      'iblt', 
                      'inbound_percent', 
                      'outbound_percent', 
                      'rank', 
                      'rerequested', 
                      'response_time', 
                      'summary', 
                      'validation_time'}
    def __init__(self, test_assertion='success'):
        self.rep = False

    def set_test_params(self):
        self.num_nodes = 3

    def setup_network(self, split=False):
        node_opts = [
            "-rpcservertimeout=0",
            "-debug=all",
            "-net.syncMempoolWithPeers=1",
            "-net.randomlyDontInv=100",
            "-use-grapheneblocks=0",
            "-excessiveblocksize=6000000",
            "-blockprioritysize=6000000",
            "-blockmaxsize=6000000"]

        self.nodes = [
            start_node(0, self.options.tmpdir, node_opts),
            start_node(1, self.options.tmpdir, node_opts),
            start_node(2, self.options.tmpdir, node_opts)
        ]

        interconnect_nodes(self.nodes)
        self.is_network_split = False
        self.sync_all()

    def extract_stats_fields(self, node):
        gni = node.getnetworkinfo()
        assert "grapheneblockstats" in gni
        tbs = gni["grapheneblockstats"]
        assert "enabled" in tbs and tbs["enabled"]
        assert set(tbs) == self.expected_stats

        return tbs

    def assert_success(self):
        # Nodes 0 and 1 should have received one block from node 2.
        assert '1 inbound and 0 outbound graphene blocks' in self.extract_stats_fields(self.nodes[0])['summary']
        assert '1 inbound and 0 outbound graphene blocks' in self.extract_stats_fields(self.nodes[1])['summary']

        # Node 2 should have sent a block to the two other nodes
        assert '0 inbound and 2 outbound graphene blocks' in self.extract_stats_fields(self.nodes[2])['summary']

    def assert_failure(self):
        try:
            self.assert_success()
        except AssertionError:
            return

        raise AssertionError('graphene block failure was expected but not encountered')

    def run_test(self):
        chain_height = self.nodes[0].getblockcount()
        assert_equal(chain_height, 200)

        logging.info("Mine a single block to get out of IBD")
        self.nodes[0].generate(1)
        self.sync_all()

        logging.info("Send 10 transactions from node0 (to its own address)")
        for i in range(10):
            self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), Decimal("10"))

        logging.info("Send 10 transactions from node1 (to its own address)")
        for i in range(10):
            self.nodes[1].sendtoaddress(self.nodes[1].getnewaddress(), Decimal("10"))

        logging.info("Send 10 transactions from node2 (to its own address)")
        for i in range(10):
            self.nodes[2].sendtoaddress(self.nodes[2].getnewaddress(), Decimal("10"))

        waitFor(180, lambda: len(self.nodes[0].getrawmempool()) == 30)
        waitFor(180, lambda: len(self.nodes[1].getrawmempool()) == 30)
        waitFor(180, lambda: len(self.nodes[2].getrawmempool()) == 30)

if __name__ == '__main__':
    MempoolSyncTest().main()
