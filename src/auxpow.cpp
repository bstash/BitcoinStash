// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 Vince Durham
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2016 Daniel Kraft
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include "auxpow.h"

#include "compat/endian.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "chainparams.h"
#include "hash.h"
#include "script/script.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation.h"

//for debugging only
#include "core_io.h"

#include <algorithm>

/* Moved from wallet.cpp.  CMerkleTx is necessary for auxpow, independent
   of an enabled (or disabled) wallet.  Always include the code.  */

const uint256 CMerkleTx::ABANDON_HASH(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));


std::vector<unsigned char> BuildChainId(int32_t chainId)
{
    std::vector<unsigned char> out;
    out.insert(out.end(), UBEGIN(chainId), UEND(chainId));
    return out;
}


std::vector<unsigned char> BuildCoinbaseData(const uint256& hash, unsigned h, int nonce, int chainId)
{
    std::vector<unsigned char> vHash = ToByteVector(hash);
    std::reverse(vHash.begin(), vHash.end());

    std::vector<unsigned char> out;

    out.insert(out.end(), UBEGIN(pchMergedMiningHeader), UEND(pchMergedMiningHeader));
    out.insert(out.end(), vHash.begin(), vHash.end());

    const int size = (1 << h);
    out.insert(out.end(), UBEGIN(size), UEND(size));
    out.insert(out.end(), UBEGIN(nonce), UEND(nonce));

    std::vector<unsigned char> vchainId = BuildChainId(chainId);
    out.insert(out.end(), vchainId.begin(), vchainId.end());
    return out;
}


// extract all relevant data from coinbas
// Returns true if all data present
bool ParseAuxPowData(const CScript &script, std::vector<unsigned char> &vchRootHash,
                                uint32_t &nSize, uint32_t &nNonce, int32_t &chainId,
                                std::string &fail_reason)
{
    CScript::const_iterator pc =
        std::search(script.begin(), script.end(), UBEGIN(pchMergedMiningHeader), UEND(pchMergedMiningHeader));

    if (pc == script.end()){
        fail_reason = "Merge mining header does not exist";
        return false;
    }

    // Enforce only one chain merkle root by checking that a single instance of the merged
    // mining header exists just before.
    if (script.end() != std::search(pc + 1, script.end(), UBEGIN(pchMergedMiningHeader), UEND(pchMergedMiningHeader))){
        fail_reason = "Multiple merged mining headers in coinbase";
        return false;
    }
    if (script.end() - pc < sizeof(pchMergedMiningHeader)+32+8+4){
        fail_reason = "Data in coinbase not big enough to contain merge mine data";
        return false;
    }

    // Get hash from coinbase
    pc += sizeof(pchMergedMiningHeader);
    assert(vchRootHash.empty());
    vchRootHash.insert(vchRootHash.end(), pc, pc+32);

    // Get nSize and nNonce
    pc += 32;
    memcpy(&nSize, &pc[0], 4);
    nSize = le32toh(nSize);
    memcpy(&nNonce, &pc[4], 4);
    nNonce = le32toh (nNonce);

    // Get chainId
    pc += 8;

    memcpy(&chainId, &pc[0], 4);
    chainId = le32toh(chainId);

    return true;
}



// for checking auxpow block coinbase script for chain Id
bool CheckAuxPowCoinbase(const CScript& cb_script, int32_t ourChainId)
{
    std::vector<unsigned char> hash;
    uint32_t size;
    uint32_t nonce;
    int32_t chainId;
    std::string fail_reason;
    if(ParseAuxPowData(cb_script, hash, size, nonce, chainId, fail_reason))
    {
        /*
        if our block has parseable aux pow data in the coinbase, make sure
        the chain id It contains is ours. This prevents the block from being
        resubmitted as the parent block to a another block, since we reject
        parent block with the same chain Id as ours.
        */
        if(chainId != ourChainId)
            return error("%s : chainId %i found on block coinbase is not ours", __func__, chainId);
    }
    return true;
}

// for checking header
bool CheckAuxPowHeader(const CBlockHeader& header, const Config &config)
{
    int32_t ourChainId = config.GetChainParams().GetConsensus().nAuxpowChainId;

    /* If there is no auxpow, just check the block hash.  */
    if (!header.auxpow)
    {
        if (header.IsAuxPow()){
            return error("%s : no auxpow on block with auxpow version",
                         __func__);
        }
        if (!CheckProofOfWork(header.GetHash(), header.nBits, config)){
            return error("%s : non-AUX proof of work failed", __func__);

        }
        return true;
    }

    /* We have auxpow.  Check it.  */
    if (!header.IsAuxPow()){
        return error("%s : auxpow on block with non-auxpow version", __func__);
    }
    if (!header.auxpow->check(header.GetHash(), ourChainId)){
        return error("%s : AUX POW is not valid", __func__);
    }
    if (!CheckProofOfWork(header.auxpow->getParentBlockPoWHash(), header.nBits, config)){
        return error("%s : AUX proof of work failed", __func__);
        }

    return true;
}


void CMerkleTx::SetMerkleBranch(const CBlockIndex* pindex, int posInBlock)
{
    // Update the tx's hashBlock
    hashBlock = pindex->GetBlockHash();

    // set the position of the transaction in the block
    nIndex = posInBlock;
}

void CMerkleTx::InitMerkleBranch(const CBlock& block, int posInBlock)
{
    hashBlock = block.GetHash();
    nIndex = posInBlock;
    vMerkleBranch = BlockMerkleBranch(block, nIndex);
}

int CMerkleTx::GetDepthInMainChain(const CBlockIndex* &pindexRet) const
{
    if (hashUnset())
        return 0;

    AssertLockHeld(cs_main);

    // Find the block it claims to be in
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    pindexRet = pindex;
    return ((nIndex == -1) ? (-1) : 1) * (chainActive.Height() - pindex->nHeight + 1);
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase())
        return 0;
    return std::max(0, (COINBASE_MATURITY+1) - GetDepthInMainChain());
}

bool CMerkleTx::AcceptToMemoryPool(const Amount& nAbsurdFee, CValidationState& state)
{
    return ::AcceptToMemoryPool(GetConfig(), mempool, state, tx, true, nullptr, false, nAbsurdFee);
}

/* ************************************************************************** */

bool CAuxPow::check(const uint256& hashAuxBlock, int ourChainId) const
{
    if (nIndex != 0){
        return error("AuxPow is not a generate");
    }

    if (vChainMerkleBranch.size() > 30){
        return error("Aux POW chain merkle branch too long");
    }

    // Get auxpow chain merkle root
    const uint256 nRootHash
      = CheckMerkleBranch(hashAuxBlock, vChainMerkleBranch, nChainIndex);
    std::vector<unsigned char> vchRootHash(nRootHash.begin(), nRootHash.end());
    std::reverse(vchRootHash.begin(), vchRootHash.end()); // correct endian

    // Check that we, the auxpow coinbase transaction, are in the parent block merkle tree
    if (CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex)
          != parentBlock.hashMerkleRoot)
        return error("Aux POW merkle root incorrect");

    // Parse aux pow data from coinbase
    std::vector<unsigned char> vchRootHashInCoinbase;
    uint32_t nSize;
    uint32_t nNonce;
    int32_t parentChainId;
    std::string fail_reason;
    if(!ParseAuxPowData(tx->vin[0].scriptSig, vchRootHashInCoinbase, nSize, nNonce, parentChainId,
                        fail_reason)){
        return error(fail_reason.c_str());

    }
    if (!std::equal(vchRootHashInCoinbase.begin(), vchRootHashInCoinbase.end(), vchRootHash.begin()))
        return error("Aux POW missing chain merkle root in parent coinbase");


    const unsigned merkleHeight = vChainMerkleBranch.size();
    if (nSize != (1u << merkleHeight)){
        return error("Aux POW merkle branch size %i does not match size in parent coinbase %i", nSize, 1u << merkleHeight);
    }

    if (nChainIndex != getExpectedIndex (nNonce, ourChainId, merkleHeight)){
        return error("Aux POW wrong index");
    }

    if (parentChainId == ourChainId){
        return error("Aux POW parent has our chain ID");
    }

    return true;
}

int CAuxPow::getExpectedIndex (uint32_t nNonce, int nChainId, unsigned h)
{
  // Choose a pseudo-random slot in the chain merkle tree
  // but have it be fixed for a size/nonce/chain combination.
  //
  // This prevents the same work from being used twice for the
  // same chain while reducing the chance that two chains clash
  // for the same slot.

  /* This computation can overflow the uint32 used.  This is not an issue,
     though, since we take the mod against a power-of-two in the end anyway.
     This also ensures that the computation is, actually, consistent
     even if done in 64 bits as it was in the past on some systems.

     Note that h is always <= 30 (enforced by the maximum allowed chain
     merkle branch length), so that 32 bits are enough for the computation.  */

  uint32_t rand = nNonce;
  rand = rand * 1103515245 + 12345;
  rand += nChainId;
  rand = rand * 1103515245 + 12345;

  return rand % (1u << h);
}

uint256 CAuxPow::CheckMerkleBranch (uint256 hash,
                            const std::vector<uint256>& vMerkleBranch,
                            int nIndex)
{
  if (nIndex == -1)
    return uint256 ();
  for (std::vector<uint256>::const_iterator it(vMerkleBranch.begin ());
       it != vMerkleBranch.end (); ++it)
  {
    if (nIndex & 1)
      hash = Hash (BEGIN (*it), END (*it), BEGIN (hash), END (hash));
    else
      hash = Hash (BEGIN (hash), END (hash), BEGIN (*it), END (*it));
    nIndex >>= 1;
  }
  return hash;
}



void CAuxPow::initAuxPow(CBlockHeader& header, int32_t parentChainId)
{
  /* Set auxpow flag right now, since we take the block hash below.  */
  header.SetAuxPowVersion(true);

  /* Build a minimal coinbase script input for merge-mining.  */
  const uint256 blockHash = header.GetHash ();
  std::vector<unsigned char> inputData = BuildCoinbaseData(blockHash, 0, 7, parentChainId);
    

  /* Fake a parent-block coinbase with just the required input
     script and no outputs.  */
  CMutableTransaction coinbase;
  coinbase.vin.resize(1);
  coinbase.vin[0].prevout.SetNull();
  coinbase.vin[0].scriptSig = (CScript () << inputData);
  assert (coinbase.vout.empty());
  CTransactionRef coinbaseRef = MakeTransactionRef(coinbase);

  /* Build a fake parent block with the coinbase.  */
  CBlock parent;
  parent.nVersion = 1;
  parent.vtx.resize(1);
  parent.vtx[0] = coinbaseRef;
  parent.hashMerkleRoot = BlockMerkleRoot(parent);

  /* Construct the auxpow object.  */
  header.SetAuxPow(new CAuxPow(coinbaseRef));
  assert (header.auxpow->vChainMerkleBranch.empty());
  header.auxpow->nChainIndex = 0;
  assert (header.auxpow->vMerkleBranch.empty());
  header.auxpow->nIndex = 0;
  header.auxpow->parentBlock = parent;
}
