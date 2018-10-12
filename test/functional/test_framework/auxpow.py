#!/usr/bin/env python
# Copyright (c) 2014 Daniel Kraft
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# General code for auxpow testing.  This includes routines to
# solve an auxpow and to generate auxpow blocks.

import binascii
import hashlib
import struct
from .mininode import ser_uint256, ser_uint256_vector

class CAuxPow():
    def __init__(self):
        # coinbase tx of parent block that contains link to child block
        self.tx = None 
        # hash of block containing above coinbase
        self.hashBlock = None 
        # merkle branches proving that coinbase belongs in merkle trie
        self.vMerkleBranch = [] 
        # nIndex must always be zero
        self.nIndex = 0
        # merkle branch that places hash of child block in merkle trie 
        self.vChainMerkleBranch = []
        # index of the hash of the child block
        self.nChainIndex = 0
        # parent block header
        self.parentBlock = None

    def serialize(self):
        r = b""
        r += self.tx.serialize()
        r += ser_uint256(self.hashBlock)
        r += ser_uint256_vector(self.vMerkleBranch)
        r += struct.pack("<i", self.nIndex)
        r += ser_uint256_vector(self.vChainMerkleBranch)
        r += struct.pack("<i", self.nChainIndex)
        r += self.parentBlock.serialize()
        return r

def buildCoinbase(block):
  coinbase = "fabe6d6d" #+ binascii.hexlify ("m" * 2)
  coinbase += block
  # size = 1 , nonce = 0, chainId = 1
  coinbase += "01000000" + ("00" * 4) + "01000000"
  return coinbase

def computeAuxpow(block, target, ok):
  """
  Build an auxpow object (serialised as hex string) that solves
  (ok = True) or doesn't solve (ok = False) the block.
  """
  coinbase = buildCoinbase(block)

  # Construct "vector" of transaction inputs.
  vin = "01"
  vin += ("00" * 32) + ("ff" * 4)
  vin += ("%02x" % (len (coinbase) // 2)) + coinbase
  vin += ("ff" * 4)

  # Build up the full coinbase transaction.  It consists only
  # of the input and has no outputs.
  tx = "01000000" + vin + "00" + ("00" * 4)
  txHash = doubleHashHex (tx)

  # Construct the parent block header.  It need not be valid, just good
  # enough for auxpow purposes.
  header = "01000000"
  header += "00" * 32
  header += reverseHex (txHash)
  header += "00" * 4
  header += "00" * 4
  header += "00" * 4

  # Mine the block.
  (header, blockhash) = mineBlock (header, target, ok)

  # Build the MerkleTx part of the auxpow.
  auxpow = tx
  auxpow += blockhash
  auxpow += "00"
  auxpow += "00" * 4

  # Extend to full auxpow.
  auxpow += "00"
  auxpow += "00" * 4
  auxpow += header

  return auxpow

def mineAuxpowBlock (node):
  """
  Mine an auxpow block on the given RPC connection.
  """

  auxblock = node.getauxblock ()
  target = reverseHex (auxblock['_target'])
  apow = computeAuxpow (auxblock['hash'], target, True)
  res = node.getauxblock (auxblock['hash'], apow)
  assert res

def mineBlock (header, target, ok):
  """
  Given a block header, update the nonce until it is ok (or not)
  for the given target.
  """

  data = bytearray (binascii.unhexlify (header))
  while True:
    assert data[79] < 255
    data[79] += 1
    hexData = binascii.hexlify (data)
    blockhash = doubleHashHex (hexData)
    if (ok and blockhash < target) or ((not ok) and blockhash > target):
      break

  return (hexData.hex(), blockhash)

def doubleHashHex (data):
  """
  Perform Bitcoin's Double-SHA256 hash on the given hex string.
  """

  hasher = hashlib.sha256 ()
  hasher.update (binascii.unhexlify (data))
  data = hasher.digest ()

  hasher = hashlib.sha256 ()
  hasher.update (data)
  return reverseHex (hasher.hexdigest ())

def reverseHex (data):
  """
  Flip byte order in the given data (hex string).
  """

  b = bytearray (binascii.unhexlify (data))
  b.reverse ()
  return b.hex()#binascii.hexlify (b)
