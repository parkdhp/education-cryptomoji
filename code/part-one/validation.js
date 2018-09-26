'use strict';

const { createHash } = require('crypto');
const signing = require('./signing');

/**
 * A simple validation function for transactions. Accepts a transaction
 * and returns true or false. It should reject transactions that:
 *   - have negative amounts
 *   - were improperly signed
 *   - have been modified since signing
 */
const isValidTransaction = transaction => {
  return transaction.amount < 0 ?
    false
    : signing.verify(
      transaction.source,
      transaction.source + transaction.recipient + transaction.amount,
      transaction.signature
    );
};

/**
 * Validation function for blocks. Accepts a block and returns true or false.
 * It should reject blocks if:
 *   - their hash or any other properties were altered
 *   - they contain any invalid transactions
 */
const isValidBlock = block => {
  const transactions = block.transactions.map(tx => tx.signature);
  const toHash = transactions + block.previousHash + block.nonce;
  return block.hash !== createHash('sha256').update(toHash).digest('hex') ?
    false
    : block.transactions.every(isValidTransaction);
};

/**
 * One more validation function. Accepts a blockchain, and returns true
 * or false. It should reject any blockchain that:
 *   - is a missing genesis block
 *   - has any block besides genesis with a null hash
 *   - has any block besides genesis with a previousHash that does not match
 *     the previous hash
 *   - contains any invalid blocks
 *   - contains any invalid transactions
 */
const isValidChain = blockchain => {
  const { blocks } = blockchain;
  if (blocks[0].previousHash !== null) {
    return false;
  }
  if (!blocks.slice(1).every((b, i) => b.previousHash === blocks[i].hash)) {    
    return false;
  }

  if (!blocks.every(b => isValidBlock(b))) {
    return false;
  } 

  return blocks
    .map(b => b.transactions)
    .reduce((flat, transactions) => [...flat, ...transactions])
    .every(isValidTransaction);
};

/**
 * This last one is just for fun. Become a hacker and tamper with the passed in
 * blockchain, mutating it for your own nefarious purposes. This should
 * (in theory) make the blockchain fail later validation checks;
 */
const breakChain = blockchain => {
  blockchain.blocks[0].previousHash = 'hello world';
};

module.exports = {
  isValidTransaction,
  isValidBlock,
  isValidChain,
  breakChain
};
