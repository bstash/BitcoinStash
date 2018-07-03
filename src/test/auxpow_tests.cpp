// Copyright (c) 2014-2015 Daniel Kraft
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "auxpow.h"
#include "chainparams.h"
#include "config.h"
#include "coins.h"
#include "consensus/merkle.h"
#include "primitives/block.h"
#include "script/script.h"
#include "uint256.h"
#include "utilstrencodings.h"
#include "validation.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <vector>

//for testing only
#include "core_io.h"

BOOST_FIXTURE_TEST_SUITE(auxpow_tests, BasicTestingSetup)

/* ************************************************************************** */

/**
 * Tamper with a uint256 (modify it).
 * @param num The number to modify.
 */
static void
tamperWith(uint256& num)
{
    arith_uint256 modifiable = UintToArith256(num);
    modifiable += 1;
    num = ArithToUint256(modifiable);
}

/**
* Build default coinbase script in parent block for auxpow
* @parentChainId - chain id of parent block
* @data - constructed auxpow data (without chainId)
*/
CScript buildCoinbaseScript(std::vector<unsigned char>& data)
{
    CScript scr = (CScript() << 2809 << 2013) + COINBASE_FLAGS;
    scr = (scr << OP_2 << data);
    return scr;
}

/**
 * Utility class to construct auxpow's and manipulate them.  This is used
 * to simulate various scenarios.
 */
class CAuxpowBuilder
{
public:
    /** The parent block (with coinbase, not just header).  */
    CBlock parentBlock;

    /** The auxpow's merkle branch (connecting it to the coinbase).  */
    std::vector<uint256> auxpowChainMerkleBranch;
    /** The auxpow's merkle tree index.  */
    int auxpowChainIndex;

    /**
   * Initialise everything.
   * @param baseVersion The parent block's base version to use.
   * @param chainId The parent block's chain ID to use.
   */
    CAuxpowBuilder(int baseVersion, int chainId);

    /**
   * Set the coinbase's script.
   * @param scr Set it to this script.
   */
    void setCoinbase(const CScript& scr);

    /**
   * Build the auxpow merkle branch.  The member variables will be
   * set accordingly.  This has to be done before constructing the coinbase
   * itself (which must contain the root merkle hash).  When we have the
   * coinbase afterwards, the member variables can be used to initialise
   * the CAuxPow object from it.
   * @param hashAux The merge-mined chain's block hash.
   * @param h Height of the merkle tree to build.
   * @param index Index to use in the merkle tree.
   * @return The root hash, with reversed endian.
   */
    std::vector<unsigned char> buildAuxpowChain(const uint256& hashAux, unsigned h, int index);

    /**
   * Build the finished CAuxPow object.  We assume that the auxpowChain
   * member variables are already set.  We use the passed in transaction
   * as the base.  It should (probably) be the parent block's coinbase.
   * @param tx The base tx to use.
   * @return The constructed CAuxPow object.
   */
    CAuxPow get(const CTransactionRef tx) const;

    /**
   * Build the finished CAuxPow object from the parent block's coinbase.
   * @return The constructed CAuxPow object.
   */
    inline CAuxPow
    get() const
    {
        assert(!parentBlock.vtx.empty());
        return get(parentBlock.vtx[0]);
    }

    /**
   * Build a data vector to be included in the coinbase.  It consists
   * of the aux hash, the merkle tree size and the nonce.  Optionally,
   * the header can be added as well.
   * @param header Add the header?
   * @param hashAux The aux merkle root hash.
   * @param h Height of the merkle tree.
   * @param nonce The nonce value to use.
   * @return The constructed data.
   */
    static std::vector<unsigned char> buildCoinbaseData(bool header, const std::vector<unsigned char>& auxRoot, unsigned h, int nonce, int chainId);
};

CAuxpowBuilder::CAuxpowBuilder(int baseVersion, int chainId)
    : auxpowChainIndex(-1)
{
    //parentBlock.SetBaseVersion(baseVersion, chainId);
    // TODO: need to set chain Id here
}

void CAuxpowBuilder::setCoinbase(const CScript& scr)
{
    //sets coinbase with auxpow on parent block
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vin[0].scriptSig = scr;

    parentBlock.vtx.clear();
    parentBlock.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    parentBlock.hashMerkleRoot = BlockMerkleRoot(parentBlock);
}

std::vector<unsigned char>
CAuxpowBuilder::buildAuxpowChain(const uint256& hashAux, unsigned h, int index)
{
    auxpowChainIndex = index;

    /* Just use "something" for the branch.  Doesn't really matter.  */
    auxpowChainMerkleBranch.clear();
    for (unsigned i = 0; i < h; ++i)
        auxpowChainMerkleBranch.push_back(ArithToUint256(arith_uint256(i)));

    const uint256 hash = CAuxPow::CheckMerkleBranch(hashAux, auxpowChainMerkleBranch, index);

    std::vector<unsigned char> res = ToByteVector(hash);
    std::reverse(res.begin(), res.end());
    return res;
}

CAuxPow CAuxpowBuilder::get(const CTransactionRef tx) const
{
    LOCK(cs_main);
    CAuxPow res(tx);
    res.InitMerkleBranch(parentBlock, 0);

    res.vChainMerkleBranch = auxpowChainMerkleBranch;
    res.nChainIndex = auxpowChainIndex;
    res.parentBlock = parentBlock;

    return res;
}

std::vector<unsigned char>
CAuxpowBuilder::buildCoinbaseData(bool header, const std::vector<unsigned char>& auxRoot,
                                  unsigned h, int nonce, int chainId)
{

    std::vector<unsigned char> reverse_auxroot = auxRoot;
    std::reverse(reverse_auxroot.begin(), reverse_auxroot.end());
    uint256 root(reverse_auxroot);

    std::vector<unsigned char> out = BuildCoinbaseData(root, h, nonce, chainId);
    if (!header){
        out.erase(out.begin(), out.begin()+4);
    }
    return out;
}

/* ************************************************************************** */

BOOST_AUTO_TEST_CASE(check_auxpow)
{
    const Config &config = GetConfig();
    const Consensus::Params& params = config.GetChainParams().GetConsensus();

    const uint16_t parentChainId = 42;
    CAuxpowBuilder builder(5, 42);
    CAuxPow auxpow;

    const uint256 hashAux = ArithToUint256(arith_uint256(12345));
    const int32_t ourChainId = params.nAuxpowChainId;
    const unsigned height = 30;
    const int nonce = 7;
    int index;

    std::vector<unsigned char> auxRoot, data;
    CScript scr;

    /* Build a correct auxpow.  The height is the maximally allowed one.  */
    index = CAuxPow::getExpectedIndex(nonce, ourChainId, height);
    auxRoot = builder.buildAuxpowChain(hashAux, height, index);
    data = CAuxpowBuilder::buildCoinbaseData(true, auxRoot, height, nonce, parentChainId);
    scr = buildCoinbaseScript(data);
    builder.setCoinbase(scr);
    BOOST_CHECK(builder.get().check(hashAux, ourChainId));

    /* Check that the auxpow is invalid if we change either the aux block's
     hash*/
    uint256 modifiedAux(hashAux);
    tamperWith(modifiedAux);
    BOOST_CHECK(!builder.get().check(modifiedAux, ourChainId));

    /* Check that the auxpow is invalid if we change the chain Id */
    BOOST_CHECK(!builder.get().check(hashAux, ourChainId + 1));

    /* Non-coinbase parent tx should fail.  Note that we can't just copy
     the coinbase literally, as we have to get a tx with different hash.  */
    const CTransactionRef oldCoinbase = builder.parentBlock.vtx[0];
    builder.setCoinbase(scr << 5);
    builder.parentBlock.vtx.push_back(oldCoinbase);
    builder.parentBlock.hashMerkleRoot = BlockMerkleRoot(builder.parentBlock);
    auxpow = builder.get(builder.parentBlock.vtx[0]);
    BOOST_CHECK(auxpow.check(hashAux, ourChainId));
    auxpow = builder.get(builder.parentBlock.vtx[1]);
    BOOST_CHECK(!auxpow.check(hashAux, ourChainId));

    /* The parent chain can't have the same chain ID as ours.  */
    CAuxpowBuilder builder2(builder);
    data = CAuxpowBuilder::buildCoinbaseData(true, auxRoot, height, nonce, 100);
    scr = buildCoinbaseScript(data);
    builder2.setCoinbase(scr);
    BOOST_CHECK(builder2.get().check(hashAux, ourChainId));

    data = CAuxpowBuilder::buildCoinbaseData(true, auxRoot, height, nonce, ourChainId);
    scr = buildCoinbaseScript(data);
    builder2.setCoinbase(scr);
    BOOST_CHECK(!builder2.get().check(hashAux, ourChainId));

    /* TODO, missing chain id on parent block is not allowed */

    //

    /* Disallow too long merkle branches.  */
    builder2 = builder;
    index = CAuxPow::getExpectedIndex(nonce, ourChainId, height + 1);
    auxRoot = builder2.buildAuxpowChain(hashAux, height + 1, index);
    data = CAuxpowBuilder::buildCoinbaseData(true, auxRoot, height + 1, nonce, parentChainId);
    scr = buildCoinbaseScript(data);
    builder2.setCoinbase(scr);
    BOOST_CHECK(!builder2.get().check(hashAux, ourChainId));

    /* Verify that we compare correctly to the parent block's merkle root.  */
    builder2 = builder;
    BOOST_CHECK(builder2.get().check(hashAux, ourChainId));
    tamperWith(builder2.parentBlock.hashMerkleRoot);
    BOOST_CHECK(!builder2.get().check(hashAux, ourChainId));

    /* Build a block without merge mining header, it will not be accepted  */
    builder2 = builder;
    index = CAuxPow::getExpectedIndex(nonce, ourChainId, height);
    auxRoot = builder2.buildAuxpowChain(hashAux, height, index);
    data = CAuxpowBuilder::buildCoinbaseData(false, auxRoot, height, nonce, parentChainId);
    scr = buildCoinbaseScript(data);
    builder2.setCoinbase(scr);
    BOOST_CHECK(!builder2.get().check(hashAux, ourChainId));

    /* However, various attempts at smuggling two roots in should be detected.  */
    // TODO: need to add aux chain ID's.. here , is this test needed??
    const std::vector<unsigned char> wrongAuxRoot = builder2.buildAuxpowChain(modifiedAux, height, index);
    std::vector<unsigned char> data2 = CAuxpowBuilder::buildCoinbaseData(true, wrongAuxRoot, height, nonce, parentChainId);
    builder2.setCoinbase(CScript() << data << data2);
    BOOST_CHECK(!builder2.get().check(hashAux, ourChainId));
    builder2.setCoinbase(CScript() << data2 << data);
    BOOST_CHECK(!builder2.get().check(hashAux, ourChainId));

    data = CAuxpowBuilder::buildCoinbaseData(true, auxRoot, height, nonce, parentChainId);
    builder2.setCoinbase(CScript() << data << data2);
    BOOST_CHECK(!builder2.get().check(hashAux, ourChainId));
    builder2.setCoinbase(CScript() << data2 << data);
    BOOST_CHECK(!builder2.get().check(hashAux, ourChainId));

    data2 = CAuxpowBuilder::buildCoinbaseData(false, wrongAuxRoot,
        height, nonce, parentChainId);
    builder2.setCoinbase(CScript() << data << data2);
    BOOST_CHECK(builder2.get().check(hashAux, ourChainId));
    builder2.setCoinbase(CScript() << data2 << data);
    BOOST_CHECK(builder2.get().check(hashAux, ourChainId));

    /* Verify that the appended nonce/size values are checked correctly.  */
    data = CAuxpowBuilder::buildCoinbaseData(true, auxRoot, height, nonce, parentChainId);
    builder2.setCoinbase(CScript() << data);
    BOOST_CHECK(builder2.get().check(hashAux, ourChainId));

    data.pop_back();
    builder2.setCoinbase(CScript() << data);
    BOOST_CHECK(!builder2.get().check(hashAux, ourChainId));

    data = CAuxpowBuilder::buildCoinbaseData(true, auxRoot, height - 1, nonce, parentChainId);
    builder2.setCoinbase(CScript() << data);
    BOOST_CHECK(!builder2.get().check(hashAux, ourChainId));

    data = CAuxpowBuilder::buildCoinbaseData(true, auxRoot, height, nonce + 3, parentChainId);
    builder2.setCoinbase(CScript() << data);
    BOOST_CHECK(!builder2.get().check(hashAux, ourChainId));

    /* Put the aux hash in an invalid merkle tree position.  */

    auxRoot = builder.buildAuxpowChain(hashAux, height, index + 1);
    data = CAuxpowBuilder::buildCoinbaseData(true, auxRoot, height, nonce, parentChainId);
    builder2.setCoinbase(CScript() << data);
    BOOST_CHECK(!builder2.get().check(hashAux, ourChainId));

    auxRoot = builder.buildAuxpowChain(hashAux, height, index);
    data = CAuxpowBuilder::buildCoinbaseData(true, auxRoot, height, nonce, parentChainId);
    builder2.setCoinbase(CScript() << data);
    BOOST_CHECK(builder2.get().check(hashAux, ourChainId));
}

/* ************************************************************************** */

/**
 * Mine a block (assuming minimal difficulty) that either matches
 * or doesn't match the difficulty target specified in the block header.
 * @param block The block to mine (by updating nonce).
 * @param ok Whether the block should be ok for PoW.
 * @param nBits Use this as difficulty if specified.
 */
static void
mineBlock(CBlockHeader& block, bool ok, int nBits = -1)
{
    if (nBits == -1)
        nBits = block.nBits;

    arith_uint256 target;
    target.SetCompact(nBits);

    block.nNonce = 0;
    while (true) {
        const bool nowOk = (UintToArith256(block.GetHash()) <= target);
        if ((ok && nowOk) || (!ok && !nowOk))
            break;

        ++block.nNonce;
    }

    if (ok)
        BOOST_CHECK(CheckProofOfWork(block.GetHash(), nBits, GetConfig()));
    else
        BOOST_CHECK(!CheckProofOfWork(block.GetHash(), nBits, GetConfig()));
}

BOOST_AUTO_TEST_CASE(auxpow_pow)
{
    /* Use regtest parameters to allow mining with easy difficulty.  */
    SelectParams(CBaseChainParams::REGTEST);

    const Config &config = GetConfig();
    const Consensus::Params& params = config.GetChainParams().GetConsensus();

    const arith_uint256 target = (~arith_uint256(0) >> 1);
    CBlockHeader header;
    header.nBits = target.GetCompact();

    const int32_t ourChainId = params.nAuxpowChainId;
    const uint16_t parentChainId = 42;

    /* Verify non auxpow blocks  */
    // Valid non auxpow block
    header.nVersion = 1;
    mineBlock(header, true);
    BOOST_CHECK(CheckAuxPowHeader(header, config));

    header.SetAuxPowVersion(false);
    mineBlock(header, true);
    BOOST_CHECK(CheckAuxPowHeader(header, config));

    // Invalid non auxpow block
    header.SetAuxPowVersion(false);
    mineBlock(header, false);
    BOOST_CHECK(!CheckAuxPowHeader(header, config));

    // test invalid block with version set to auxpow but
    // with no auxpow
    header.SetAuxPowVersion(true);
    mineBlock(header, true);
    BOOST_CHECK(!CheckAuxPowHeader(header, config));

    // TODO: test block with version set to non auxpow
    // but with auxpow

    /* ****************************************** */
    /* Check the case that the block has auxpow.  */

    CAuxpowBuilder builder(5, 42);
    CAuxPow auxpow;
    const unsigned height = 3;
    const int nonce = 7;
    const int index = CAuxPow::getExpectedIndex(nonce, ourChainId, height);
    std::vector<unsigned char> auxRoot, data;

    /* Valid auxpow, PoW check of parent block.  */
    header.SetAuxPowVersion(true);
    auxRoot = builder.buildAuxpowChain(header.GetHash(), height, index);
    data = CAuxpowBuilder::buildCoinbaseData(true, auxRoot, height, nonce, parentChainId);
    builder.setCoinbase(CScript() << data);
    mineBlock(builder.parentBlock, false, header.nBits);
    header.SetAuxPow(new CAuxPow(builder.get()));
    BOOST_CHECK(!CheckAuxPowHeader(header, config)); // TODO: is this right?
    mineBlock(builder.parentBlock, true, header.nBits);
    header.SetAuxPow(new CAuxPow(builder.get()));
    BOOST_CHECK(CheckAuxPowHeader(header, config)); // TODO: is this right?

    //TODO: what is this?
    /* Mismatch between auxpow being present and block.nVersion.  Note that
     block.SetAuxPow sets also the version and that we want to ensure
     that the block hash itself doesn't change due to version changes.
     This requires some work arounds.  */
    header.SetAuxPowVersion(false);
    const uint256 hashAux = header.GetHash();
    auxRoot = builder.buildAuxpowChain(hashAux, height, index);
    data = CAuxpowBuilder::buildCoinbaseData(true, auxRoot, height, nonce, parentChainId);
    builder.setCoinbase(CScript() << data);
    mineBlock(builder.parentBlock, true, header.nBits);
    header.SetAuxPow(new CAuxPow(builder.get()));
    BOOST_CHECK(hashAux != header.GetHash());
    header.SetAuxPowVersion(false);
    BOOST_CHECK(hashAux == header.GetHash());
    BOOST_CHECK(!CheckAuxPowHeader(header, config));

    /* Modifying the block invalidates the PoW.  */
    header.SetAuxPowVersion(true);
    auxRoot = builder.buildAuxpowChain(header.GetHash(), height, index);
    data = CAuxpowBuilder::buildCoinbaseData(true, auxRoot, height, nonce, parentChainId);
    builder.setCoinbase(CScript() << data);
    mineBlock(builder.parentBlock, true, header.nBits);
    header.SetAuxPow(new CAuxPow(builder.get()));
    BOOST_CHECK(CheckAuxPowHeader(header, config));
    tamperWith(header.hashMerkleRoot);
    BOOST_CHECK(!CheckAuxPowHeader(header, config));
}


/* ************************************************************************** */

BOOST_AUTO_TEST_SUITE_END()
