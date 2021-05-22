------------------------------------------------------------------------------
-- Merkle bridge contract
------------------------------------------------------------------------------

-- Internal type check function
-- @type internal
-- @param x variable to check
-- @param t (string) expected type
local function _typecheck(x, t)
  if (x and t == 'address') then
    assert(type(x) == 'string', "address must be string type")
    -- check address length
    assert(52 == #x, string.format("invalid address length: %s (%s)", x, #x))
    -- check character
    local invalidChar = string.match(x, '[^123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]')
    assert(nil == invalidChar, string.format("invalid address format: %s contains invalid char %s", x, invalidChar or 'nil'))
  elseif (x and t == 'ethaddress') then
    assert(type(x) == 'string', "eth address must be string type")
    -- check address length
    assert(40 == #x, string.format("invalid eth address length: %s (%s)", x, #x))
    -- check character
    local invalidChar = string.match(x, '[^0123456789abcdef]')
    assert(nil == invalidChar, string.format("invalid eth address format: %s contains invalid char %s", x, invalidChar or 'nil'))
  elseif (x and t == 'ubig') then
    -- check unsigned bignum
    assert(bignum.isbignum(x), string.format("invalid type: %s != %s", type(x), t))
    assert(x >= bignum.number(0), string.format("%s must be positive number", bignum.tostring(x)))
  elseif (x and t == 'str128') then
    assert(type(x) == 'string', "str128 must be string type")
    -- check address length
    assert(128 >= #x, string.format("too long str128 length: %s", #x))
  else
    -- check default lua types
    assert(type(x) == t, string.format("invalid type: %s != %s", type(x), t or 'nil'))
  end
end

-- Stores latest finalised bridge contract state root of ethereum blockchain at regular intervals.
-- Enables Users to verify state information of the connected chain 
-- using merkle proofs for the finalised state root.
state.var {
    -- Trie root of the opposit side bridge contract. _mints and _unlocks require a merkle proof
    -- of state inclusion in this last Root.
    -- (0x hex string)
    _anchorRoot = state.value(),
    -- Height of the last block anchored
    -- (uint)
    _anchorHeight = state.value(),

    -- _tAnchor is the anchoring periode of the bridge
    -- (uint)
    _tAnchor = state.value(),
    -- _tFinal is the time after which the bridge operator consideres a block finalised
    -- this value is only useful if the anchored chain doesn't have LIB
    -- (uint)
    _tFinal = state.value(),
    -- _aergoErc20Bytes is the Aergo token contract address bytes on Ethereum
    -- (Ethereum address)
    _aergoErc20Bytes = state.value(),
    -- unfreezeFee gives a fee to the tx sender to enable free unfreezing of aergo on mainnet
    _unfreezeFee = state.value(),
    -- oracle that controls this bridge.
    _oracle = state.value(),

    -- Registers locked balances per account reference: user provides merkle proof of locked balance
    -- (account ref string) -> (string uint)
    _locks = state.map(),
    -- Registers unlocked balances per account reference: prevents unlocking more than was burnt
    -- (account ref string) -> (string uint)
    _unlocks = state.map(),
    -- Registers burnt balances per account reference : user provides merkle proof of burnt balance
    -- (account ref string) -> (string uint)
    _burns = state.map(),
    -- Registers minted balances per account reference : prevents minting more than what was locked
    -- (account ref string) -> (string uint)
    _mints = state.map(),
    -- Registers unfreezed balances per account reference : prevents unfreezing more than was locked
    -- (account ref string) -> (string uint)
    _unfreezes = state.map(),
    -- _bridgeTokens keeps track of tokens that were received through the bridge
    -- (Ethereum address) -> (Aergo address)
    _bridgeTokens = state.map(),
    -- _mintedTokens is the same as BridgeTokens but keys and values are swapped
    -- _mintedTokens is used for preventing a minted token from being locked instead of burnt.
    -- (Aergo address) -> (Ethereum address)
    _mintedTokens = state.map(),

    -- Registers burnt token's block height per account reference : user provides merkle proof of burnt token's block height
    -- (account ref string) -> (string block height)
    _burnsARC2 = state.map(),
    -- Registers locked token's block height per account reference: user provides merkle proof of locked token's block height
    -- (account ref string) -> (string block height)
    _mintsARC2 = state.map(),

    -- _bridgeNFTs keeps track of NFTs that were received through the bridge
    -- (Ethereum address) -> (Aergo address)
    _bridgeNFTs = state.map(),
    -- _mintedNFTs is the same as _bridgeNFTs but keys and values are swapped
    -- _mintedNFTs is used for preventing a minted NFT from being locked instead of burnt.
    -- (Aergo address) -> (Ethereum address)
    _mintedNFTs = state.map(),
}


--------------------- Utility Functions -------------------------

local function _onlyOracle()
    assert(system.getSender() == _oracle:get(), string.format("Only oracle can call, expected: %s, got: %s", _oracle:get(), system.getSender()))
end


-- Convert hex string to lua bytes
-- @type    internal
-- @param   hexString (hex string) hex string without 0x
-- @return  (string bytes) bytes of hex string
local function _abiEncode(hexString)
    return (hexString:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

-- Ethereum Patricia State Trie Merkle proof verification
-- @type    query
-- @param   mapKey (string bytes) key in solidity map
-- @param   mapPosition (uint) position of mapping state var in solidity contract
-- @param   value (string bytes) value of mapKey in solidity map at mapPosition
-- @param   merkleProof ([]0x hex string) merkle proof of inclusion of mapKey, value in _anchorRoot
-- @return  (bool) merkle proof of inclusion is valid
function verifyDepositProof(mapKey, mapPosition, value, merkleProof)
    -- map key is always >= 32 bytes so no padding needed
    paddedPosition = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" .. string.char(mapPosition)
    key = crypto.keccak256(mapKey..paddedPosition)
    return crypto.verifyProof(key, value, _anchorRoot:get(), unpack(merkleProof))
end

-- deploy new contract
-- @type    internal
-- @param   tokenOrigin (ethaddress) Ethereum address without 0x of token locked used as pegged token name
local function _deployMintableToken(tokenOrigin)
    addr, success = contract.deploy(mintedARC1Code, tokenOrigin)
    assert(success, "failed to create peg token contract")
    return addr
end

-- lock tokens in the bridge contract
-- @type    internal
-- @param   tokenAddress (address) Aergo address of token locked
-- @param   amount (ubig) amount of tokens to send
-- @param   receiver (ethaddress) Ethereum address without 0x of receiver accross the bridge
-- @event   lock(receiver, amount, tokenAddress)
local function _lock(tokenAddress, amount, receiver)
    _typecheck(receiver, 'ethaddress')
    _typecheck(amount, 'ubig')
    assert(_mintedTokens[tokenAddress] == nil, "this token was minted by the bridge so it should be burnt to transfer back to origin, not locked")
    assert(amount > bignum.number(0), "amount must be positive")

    -- Add locked amount to total
    local accountRef =  _abiEncode(receiver) .. tokenAddress
    local old = _locks[accountRef]
    local lockedBalance
    if old == nil then
        lockedBalance = amount
    else
        lockedBalance = bignum.number(old) + amount
        -- bignum overflow raises error
    end
    _locks[accountRef] = bignum.tostring(lockedBalance)
    contract.event("lock", receiver, amount, tokenAddress)
end

-- Create a new bridge contract
-- @type    __init__
-- @param   aergoErc20 (ethaddress) Ethereum address without 0x of aergoErc20
-- @param   tAnchor (uint) anchoring periode
-- @param   tFinal (uint) finality of anchored chain
-- @param   unfreeze_fee (ubig) fee taken when a thirs party unfreezes
function constructor(aergoErc20, tAnchor, tFinal, unfreeze_fee)
    _typecheck(aergoErc20, 'ethaddress')
    _typecheck(unfreeze_fee, 'ubig')
    _aergoErc20Bytes:set(_abiEncode(aergoErc20))
    _tAnchor:set(tAnchor)
    _tFinal:set(tFinal)
    _anchorRoot:set("constructor")
    _anchorHeight:set(0)
    _unfreezeFee:set(bignum.number(1000))
    -- the oracle is set to the sender who must transfer ownership to oracle contract
    -- with oracleUpdate(), once deployed
    _oracle:set(system.getSender())
end

--------------------- Bridge Operator Functions -------------------------

function default()
    contract.event("initializeVault", system.getSender(), system.getAmount())
    -- needed to send the vault funds when starting the bridge
    -- consider disabling after 1st transfer so users don't send 
    -- funds by mistake
end

-- Replace the oracle with another one
-- @type    call
-- @param   newOracle (address) Aergo address of the new oracle
-- @event   oracleUpdate(proposer, newOracle)
function oracleUpdate(newOracle)
    _onlyOracle()
    _oracle:set(newOracle)
    contract.event("oracleUpdate", system.getSender(), newOracle)
end

-- Register a new anchor
-- @type    call
-- @param   root (0x hex string) Ethereum storage root
-- @param   height (uint) block height of root
-- @event   newAnchor(proposer, height, root)
function newAnchor(root, height)
    _onlyOracle()
    -- check Height to prevent spamming and leave minimum time for users to make transfers.
    assert(height > _anchorHeight:get() + _tAnchor:get(), "Next anchor height not reached")
    _anchorRoot:set(root)
    _anchorHeight:set(height)
    contract.event("newAnchor", system.getSender(), height, root)
end


-- Register new anchoring periode
-- @type    call
-- @param   tAnchor (uint) new anchoring periode
-- @event   tAnchorUpdate(proposer, tAnchor)
function tAnchorUpdate(tAnchor)
    _onlyOracle()
    _tAnchor:set(tAnchor)
    contract.event("tAnchorUpdate", system.getSender(), tAnchor)
end

-- Register new finality of anchored chain
-- @type    call
-- @param   tFinal (uint) new finality of anchored chain
-- @event   tFinalUpdate(proposer, tFinal)
function tFinalUpdate(tFinal)
    _onlyOracle()
    _tFinal:set(tFinal)
    contract.event("tFinalUpdate", system.getSender(), tFinal)
end

-- Register new unfreezing fee for delegated unfreeze service
-- @type    call
-- @param   fee (ubig) new unfreeze fee
-- @event   unfreezeFeeUpdate(proposer, fee)
function unfreezeFeeUpdate(fee)
    _onlyOracle()
    _unfreezeFee:set(fee)
    contract.event("unfreezeFeeUpdate", system.getSender(), fee)
end

--------------------- User Transfer Functions -------------------------

-- The ARC1 smart contract calls this function on the recipient after a 'transfer'
-- @type    call
-- @param   operator    (address) the address which called token 'transfer' function
-- @param   from        (address) the sender's address
-- @param   value       (ubig) an amount of token to send
-- @param   receiver    (ethaddress) Ethereum address without 0x of receiver accross the bridge
function tokensReceived(operator, from, value, receiver)
    return _lock(system.getSender(), value, receiver)
end


-- mint a token locked on Ethereum
-- AergoERC20 is locked on ethereum like any other tokens, but it is not minted, it is unfreezed.
-- anybody can mint, the receiver is the account who's locked balance is recorded
-- @type    call
-- @param   receiver (address) Aergo address of receiver
-- @param   balance (ubig) total balance of tokens locked on Ethereum
-- @param   tokenOrigin (ethaddress) Ethereum address without 0x of ERC20 token locked
-- @param   merkleProof ([]0x hex string) merkle proof of inclusion of locked balance on Ethereum
-- @return  (address, uint) pegged token Aergo address, minted amount
-- @event   mint(minter, receiver, amount, tokenOrigin)
function mint(receiver, balance, tokenOrigin, merkleProof)
    _typecheck(receiver, 'address')
    _typecheck(balance, 'ubig')
    _typecheck(tokenOrigin, 'ethaddress')
    assert(balance > bignum.number(0), "mintable balance must be positive")
    tokenOriginBytes = _abiEncode(tokenOrigin)
    assert(tokenOriginBytes ~= _aergoErc20Bytes:get(), "Aergo cannot be minted, must be unfreezed")

    -- Verify merkle proof of locked balance
    local accountRef = receiver .. tokenOriginBytes
    -- Locks is the 6th variable of eth_merkle_bridge.col so mapPosition = 5
    if not verifyDepositProof(accountRef, 5, bignum.tobyte(balance), merkleProof) then
        error("failed to verify deposit balance merkle proof")
    end
    -- Calculate amount to mint
    local amountToTransfer
    mintedSoFar = _mints[accountRef]
    if mintedSoFar == nil then
        amountToTransfer = balance
    else
        amountToTransfer  = balance - bignum.number(mintedSoFar)
    end
    assert(amountToTransfer > bignum.number(0), "make a deposit before minting")
    -- Deploy or get the minted token
    local mintAddress
    if _bridgeTokens[tokenOrigin] == nil then
        -- Deploy new mintable token controlled by bridge
        mintAddress = _deployMintableToken(tokenOrigin)
        _bridgeTokens[tokenOrigin] = mintAddress
        _mintedTokens[mintAddress] = tokenOrigin
    else
        mintAddress = _bridgeTokens[tokenOrigin]
    end
    -- Record total amount minted
    _mints[accountRef] = bignum.tostring(balance)
    -- Mint tokens
    contract.call(mintAddress, "mint", receiver, amountToTransfer)
    contract.event("mint", system.getSender(), receiver, amountToTransfer, tokenOrigin)
    return mintAddress, amountToTransfer
end

-- burn a pegged token
-- @type    call
-- @param   receiver (ethaddress) Ethereum address without 0x of receiver
-- @param   amount (ubig) number of tokens to burn
-- @param   mintAddress (address) Aergo token contract address of pegged token to burn
-- @return  (ethaddress) Ethereum address without 0x of origin token
-- @event   brun(owner, receiver, amount, mintAddress)
function burn(receiver, amount, mintAddress)
    _typecheck(receiver, 'ethaddress')
    _typecheck(amount, 'ubig')
    assert(amount > bignum.number(0), "amount must be positive")
    local originAddress = _mintedTokens[mintAddress]
    assert(originAddress ~= nil, "cannot burn token : must have been minted by bridge")
    -- Add burnt amount to total
    local accountRef = _abiEncode(receiver .. originAddress)
    local old = _burns[accountRef]
    local burntBalance
    if old == nil then
        burntBalance = amount
    else
        burntBalance = bignum.number(old) + amount
        -- bignum overflow raises error
    end
    _burns[accountRef] = bignum.tostring(burntBalance)
    -- Burn token
    contract.call(mintAddress, "burn", system.getSender(), amount)
    contract.event("burn", system.getSender(), receiver, amount, mintAddress)
    return originAddress
end

-- mint a pegged ARC2 NFT locked on Ethereum
-- anybody can mint, the receiver is the account who's locked tokenId is recorded
-- @type    call
-- @param   receiver (address) Aergo address of receiver
-- @param   tokenId (str128) the ERC721 token ID locked on Ethereum
-- @param   lockERC721BlockNum (ubig) the block number of the tx that sends ERC721 to the Ether Merkle Bridge
-- @param   tokenOrigin (ethaddress) Ethereum address without 0x of ERC721 token locked
-- @param   merkleProof ([]0x hex string) merkle proof of inclusion of locked balance on Ethereum
-- @return  (address, uint) pegged token Aergo address, minted amount
-- @event   mintARC2(minter, receiver, tokenId, lockERC721BlockNum, tokenOrigin)
function mintARC2(receiver, tokenId, lockERC721BlockNum, tokenOrigin, merkleProof)
  _typecheck(receiver, 'address')
  _typecheck(tokenId, 'str128')
  _typecheck(lockERC721BlockNum, 'ubig')
  _typecheck(tokenOrigin, 'ethaddress')
  
  tokenOriginBytes = _abiEncode(tokenOrigin)
  
  -- Verify merkle proof of locked NFT
  local accountRef = receiver .. tokenId .. tokenOriginBytes
  -- _locksERC721 is the 10th variable of eth_merkle_bridge.col so mapPosition = 9
  if not verifyDepositProof(accountRef, 9, bignum.tobyte(lockERC721BlockNum), merkleProof) then
      error("failed to verify merkle proof of a locked NFT")
  end

  assert(_mintsARC2[accountRef] ~= bignum.tostring(lockERC721BlockNum), "already minted token")

  -- Deploy or get the minted token
  local mintAddress
  if _bridgeNFTs[tokenOrigin] == nil then
      -- Deploy new mintable NFT controlled by bridge
      mintAddress = _deployMintableNFT(tokenOrigin)
      _bridgeNFTs[tokenOrigin] = mintAddress
      _mintedNFTs[mintAddress] = tokenOrigin
  else
      mintAddress = _bridgeNFTs[tokenOrigin]
  end
  -- Record lockERC721BlockNum
  _mintsARC2[accountRef] = bignum.tostring(lockERC721BlockNum)
  -- Mint tokens
  contract.call(mintAddress, "mint", receiver, tokenId)
  contract.event("mint", system.getSender(), receiver, tokenId, lockERC721BlockNum, tokenOrigin)

  return mintAddress
end

-- Implementation of ARC2 token receiver interface
-- @param   operator    (address) a address which called token 'transfer' function
-- @param   from        (address) a sender's address
-- @param   value       (ubig) an amount of token to send
-- @param   receiver    (ethaddress) Ethereum address without 0x of receiver accross the bridge
-- @type    call
function onARC2Received(operator, from, tokenId, receiver)
  return _burnARC2(receiver, tokenId, system.getSender())
end

-- burn a pegged NFT
-- @type    call
-- @param   receiver    (ethaddress) Ethereum address without 0x of receiver
-- @param   tokenId     (str128) token Id to burn
-- @param   arc2Address (address) Aergo NFT contract address of pegged token to burn
-- @return  (string) the block number of the tx that sends ARC2 to the Aergo Merkle Bridge
-- @event   brun(owner, receiver, tokenId, burnARC2BlockNum, arc2Address)
local function _burnARC2(receiver, tokenId, arc2Address)
  _typecheck(receiver, 'ethaddress')
  _typecheck(tokenId, 'str128')
  
  local originAddress = _mintedNFTs[arc2Address]
  assert(originAddress ~= nil, "cannot burn NFT : must have been minted by bridge")

  -- record burn
  local burnARC2BlockNum = bignum.tostring(system.getBlockheight())

  local accountRef = _abiEncode(receiver .. tokenId .. originAddress)
  _burnsARC2[accountRef] = burnARC2BlockNum

  -- Burn NFT
  contract.call(arc2Address, "burn", tokenId)
  contract.event("burn", system.getSender(), receiver, tokenId, burnARC2BlockNum, arc2Address)
  
  return burnARC2BlockNum
end


-- unlock tokens
-- anybody can unlock, the receiver is the account who's burnt balance is recorded
-- @type    call
-- @param   receiver (address) Aergo address of receiver
-- @param   balance (ubig) total balance of tokens burnt on Ethereum
-- @param   tokenAddress (address) Aergo address of token to unlock
-- @param   merkleProof ([]0x hex string) merkle proof of inclusion of burnt balance on Ethereum
-- @return  (uint) unlocked amount
-- @event   unlock(unlocker, receiver, amount, tokenAddress)
function unlock(receiver, balance, tokenAddress, merkleProof)
    _typecheck(receiver, 'address')
    _typecheck(tokenAddress, 'address')
    _typecheck(balance, 'ubig')
    assert(balance > bignum.number(0), "unlockable balance must be positive")

    -- Verify merkle proof of burnt balance
    local accountRef = receiver .. tokenAddress
    -- Burns is the 8th variable of eth_merkle_bridge.col so mapPosition = 7
    if not verifyDepositProof(accountRef, 7, bignum.tobyte(balance), merkleProof) then
        error("failed to verify burnt balance merkle proof")
    end
    -- Calculate amount to unlock
    local unlockedSoFar = _unlocks[accountRef]
    local amountToTransfer
    if unlockedSoFar == nil then
        amountToTransfer = balance
    else
        amountToTransfer = balance - bignum.number(unlockedSoFar)
    end
    assert(amountToTransfer > bignum.number(0), "burn minted tokens before unlocking")
    -- Record total amount unlocked so far
    _unlocks[accountRef] = bignum.tostring(balance)
    -- Unlock tokens
    contract.call(tokenAddress, "transfer", receiver, amountToTransfer)
    contract.event("unlock", system.getSender(), receiver, amountToTransfer, tokenAddress)
    return amountToTransfer
end


-- freeze mainnet aergo
-- @type    call
-- @param   receiver (ethaddress) Ethereum address without 0x of receiver
-- @param   amount (ubig) number of tokens to freeze
-- @event   freeze(owner, receiver, amount)
function freeze(receiver, amount)
    _typecheck(receiver, 'ethaddress')
    _typecheck(amount, 'ubig')
    -- passing amount is not necessary but system.getAmount() would have to be converted to bignum anyway.
    assert(amount > bignum.number(0), "amount must be positive")
    assert(system.getAmount() == bignum.tostring(amount), "for safety and clarity, amount must match the amount sent in the tx")

    -- Add freezed amount to total
    local accountRef = _abiEncode(receiver) .. _aergoErc20Bytes:get()
    local old = _burns[accountRef]
    local freezedBalance
    if old == nil then
        freezedBalance = amount
    else
        freezedBalance = bignum.number(old) + amount
    end
    _burns[accountRef] = bignum.tostring(freezedBalance)
    contract.event("freeze", system.getSender(), receiver, amount)
end


-- unfreeze mainnet aergo
-- anybody can unfreeze, the receiver is the account who's burnt balance is recorded
-- @type    call
-- @param   receiver (address) Aergo address of receiver
-- @param   balance (ubig) total balance of tokens locked on Ethereum
-- @param   merkleProof ([]0x hex string) merkle proof of inclusion of locked balance on Ethereum
-- @return  (uint) unfreezed amount
-- @event   unfreeze(unfreezer, receiver, amount)
function unfreeze(receiver, balance, merkleProof)
    _typecheck(receiver, 'address')
    _typecheck(balance, 'ubig')
    assert(balance > bignum.number(0), "unlockable balance must be positive")

    -- Verify merkle proof of burnt balance
    local accountRef = receiver .. _aergoErc20Bytes:get()
    -- Locks is the 6th variable of eth_merkle_bridge.col so mapPosition = 5
    if not verifyDepositProof(accountRef, 5, bignum.tobyte(balance), merkleProof) then
        error("failed to verify locked balance merkle proof")
    end
    -- Calculate amount to unfreeze
    local unfreezedSoFar = _unfreezes[accountRef]
    local amountToTransfer
    if unfreezedSoFar == nil then
        amountToTransfer = balance
    else
        amountToTransfer = balance - bignum.number(unfreezedSoFar)
    end
    assert(amountToTransfer > bignum.number(0), "lock AergoERC20 on ethereum before unfreezing")
    -- Record total amount unlocked so far
    _unfreezes[accountRef] = bignum.tostring(balance)
    -- Unfreeze Aer
    if system.getSender() == receiver then
        contract.send(receiver, amountToTransfer)
    else
        -- NOTE: the minting service should check that amount to transfer will cover the fee, to not mint for nothing
        assert(amountToTransfer > _unfreezeFee:get(), "amount to transfer doesnt cover the fee")
        contract.send(receiver, amountToTransfer - _unfreezeFee:get())
        contract.send(system.getSender(), _unfreezeFee:get())
    end
    contract.event("unfreeze", system.getSender(), receiver, amountToTransfer)
    return amountToTransfer
end

mintedARC1Code = [[
------------------------------------------------------------------------------
-- Aergo Standard Token Interface (Proposal) - 20190731
------------------------------------------------------------------------------

-- A internal type check function
-- @type internal
-- @param x variable to check
-- @param t (string) expected type
local function _typecheck(x, t)
  if (x and t == 'address') then
    assert(type(x) == 'string', "address must be string type")
    -- check address length
    assert(52 == #x, string.format("invalid address length: %s (%s)", x, #x))
    -- check character
    local invalidChar = string.match(x, '[^123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]')
    assert(nil == invalidChar, string.format("invalid address format: %s contains invalid char %s", x, invalidChar or 'nil'))
  elseif (x and t == 'ubig') then
    -- check unsigned bignum
    assert(bignum.isbignum(x), string.format("invalid type: %s != %s", type(x), t))
    assert(x >= bignum.number(0), string.format("%s must be positive number", bignum.tostring(x)))
  else
    -- check default lua types
    assert(type(x) == t, string.format("invalid type: %s != %s", type(x), t or 'nil'))
  end
end

address0 = '1111111111111111111111111111111111111111111111111111'

-- The bridge token is a mintable and burnable token controlled by
-- the bridge contract. It represents tokens pegged on the other side of the 
-- bridge with a 1:1 ratio.
-- This contract is depoyed by the merkle bridge when a new type of token 
-- is transfered
state.var {
    _balances = state.map(), -- address -> unsigned_bignum
    _operators = state.map(), -- address/address -> bool

    _totalSupply = state.value(),
    _name = state.value(),
    _symbol = state.value(),
    _decimals = state.value(),

    _master = state.value(),
}

local function _callTokensReceived(from, to, value, ...)
  if to ~= address0 and system.isContract(to) then
    contract.call(to, "tokensReceived", system.getSender(), from, value, ...)
  end
end

local function _transfer(from, to, value, ...)
  _typecheck(from, 'address')
  _typecheck(to, 'address')
  _typecheck(value, 'ubig')

  assert(_balances[from] and _balances[from] >= value, "not enough balance")

  _balances[from] = _balances[from] - value
  _balances[to] = (_balances[to] or bignum.number(0)) + value

  _callTokensReceived(from, to, value, ...)

  contract.event("transfer", from, to, value)
end

local function _mint(to, value, ...)
  _typecheck(to, 'address')
  _typecheck(value, 'ubig')

  _totalSupply:set((_totalSupply:get() or bignum.number(0)) + value)
  _balances[to] = (_balances[to] or bignum.number(0)) + value

  _callTokensReceived(address0, to, value, ...)

  contract.event("transfer", address0, to, value)
end

local function _burn(from, value)
  _typecheck(from, 'address')
  _typecheck(value, 'ubig')

  assert(_balances[from] and _balances[from] >= value, "not enough balance")

  _totalSupply:set(_totalSupply:get() - value)
  _balances[from] = _balances[from] - value

  contract.event("transfer", from, address0, value)
end

-- call this at constructor
local function _init(name, symbol, decimals)
  _typecheck(name, 'string')

  _name:set(name)
  _symbol:set(symbol)
  _decimals:set(decimals)
end

------------  Main Functions ------------

-- Get a total token supply.
-- @type    query
-- @return  (ubig) total supply of this token
function totalSupply()
  return _totalSupply:get()
end

-- Get a token name
-- @type    query
-- @return  (string) name of this token
function name()
  return _name:get()
end

-- Get a token symbol
-- @type    query
-- @return  (string) symbol of this token
function symbol()
  return _symbol:get()
end

-- Get a token decimals
-- @type    query
-- @return  (number) decimals of this token
function decimals()
  return _decimals:get()
end

-- Get a balance of an owner.
-- @type    query
-- @param   owner  (address) a target address
-- @return  (ubig) balance of owner
function balanceOf(owner)
  return _balances[owner] or bignum.number(0)
end

-- Transfer sender's token to target 'to'
-- @type    call
-- @param   to      (address) a target address
-- @param   value   (ubig) an amount of token to send
-- @param   ...     addtional data, MUST be sent unaltered in call to 'tokensReceived' on 'to'
-- @event   transfer(from, to, value)
function transfer(to, value, ...)
  _transfer(system.getSender(), to, value, ...)
end

-- Get allowance from owner to spender
-- @type    query
-- @param   owner       (address) owner's address
-- @param   operator    (address) allowed address
-- @return  (bool) true/false
function isApprovedForAll(owner, operator)
  return (owner == operator) or (_operators[owner.."/".. operator] == true)
end

-- Allow operator to use all sender's token
-- @type    call
-- @param   operator  (address) a operator's address
-- @param   approved  (boolean) true/false
-- @event   approve(owner, operator, approved)
function setApprovalForAll(operator, approved)
  _typecheck(operator, 'address')
  _typecheck(approved, 'boolean')
  assert(system.getSender() ~= operator, "cannot set approve self as operator")

  _operators[system.getSender().."/".. operator] = approved

  contract.event("approve", system.getSender(), operator, approved)
end

-- Transfer 'from's token to target 'to'.
-- Tx sender have to be approved to spend from 'from'
-- @type    call
-- @param   from    (address) a sender's address
-- @param   to      (address) a receiver's address
-- @param   value   (ubig) an amount of token to send
-- @param   ...     addtional data, MUST be sent unaltered in call to 'tokensReceived' on 'to'
-- @event   transfer(from, to, value)
function transferFrom(from, to, value, ...)
  assert(isApprovedForAll(from, system.getSender()), "caller is not approved for holder")

  _transfer(from, to, value, ...)
end

-------------- Merkle Bridge functions -----------------
--------------------------------------------------------

-- Mint tokens to 'to'
-- @type        call
-- @param to    a target address
-- @param value string amount of token to mint
-- @return      success
function mint(to, value)
    assert(system.getSender() == _master:get(), "Only bridge contract can mint")
    _mint(to, value)
end

-- burn the tokens of 'from'
-- @type        call
-- @param from  a target address
-- @param value an amount of token to send
-- @return      success
function burn(from, value)
    assert(system.getSender() == _master:get(), "Only bridge contract can burn")
    _burn(from, value)
end

--------------- Custom constructor ---------------------
--------------------------------------------------------
function constructor(originAddress) 
    _init(originAddress, "PEG", "Query decimals at token origin")
    _totalSupply:set(bignum.number(0))
    _master:set(system.getSender())
    return true
end
--------------------------------------------------------

abi.register(transfer, transferFrom, setApprovalForAll, mint, burn)
abi.register_view(name, symbol, decimals, totalSupply, balanceOf, isApprovedForAll)
]]

mintedARC2Code = [[
------------------------------------------------------------------------------
-- Aergo Standard NFT Interface (Proposal) - 20210425
------------------------------------------------------------------------------

-- A internal type check function
-- @type internal
-- @param x variable to check
-- @param t (string) expected type
local function _typecheck(x, t)
    if (x and t == 'address') then
      assert(type(x) == 'string', "address must be string type")
      -- check address length
      assert(52 == #x, string.format("invalid address length: %s (%s)", x, #x))
      -- check character
      local invalidChar = string.match(x, '[^123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]')
      assert(nil == invalidChar, string.format("invalid address format: %s contains invalid char %s", x, invalidChar or 'nil'))
    elseif (x and t == 'str128') then
      assert(type(x) == 'string', "str128 must be string type")
      -- check address length
      assert(128 >= #x, string.format("too long str128 length: %s", #x))
    else
      -- check default lua types
      assert(type(x) == t, string.format("invalid type: %s != %s", type(x), t or 'nil'))
    end
end

address0 = '1111111111111111111111111111111111111111111111111111'
  
state.var {
    _name = state.value(), -- token name
    _symbol = state.value(), -- token symbol

    _owners = state.map(), -- unsigned_bignum -> address
    _balances = state.map(), -- address -> unsigned_bignum
    _tokenApprovals = state.map(), -- unsigned_bignum -> address
    _operatorApprovals = state.map(), -- address/address -> bool
}

-- call this at constructor
local function _init(name, symbol)
    _typecheck(name, 'string')
    _typecheck(symbol, 'string')
  
    _name:set(name)
    _symbol:set(symbol)
end


-- Approve `to` to operate on `tokenId`
-- Emits a approve event
local function _approve(to, tokenId) 
  _tokenApprovals[tokenId] = to
  contract.event("approve", ownerOf(tokenId), to, tokenId)
end


local function _exists(tokenId) 
  owner = _owners[tokenId] or address0
  return owner ~= address0
end

local function _callOnARC2Received(from, to, tokenId, ...)
  if to ~= address0 and system.isContract(to) then
    contract.call(to, "onARC2Received", system.getSender(), from, tokenId, ...)
  end
end


local function _mint(to, tokenId)
  _typecheck(to, 'address')
  _typecheck(tokenId, 'str128')

  assert(to ~= address0, "ARC2: mint - to the zero address")
  assert(not _exists(tokenId), "ARC2: mint - already minted token")
  
  _balances[to] = (_balances[to] or bignum.number(0)) + 1
  _owners[tokenId] = to
  
  contract.event("transfer", address0, to, tokenId)
end


local function _burn(tokenId)
  _typecheck(tokenId, 'str128')

  owner = ownerOf(tokenId)
  
  -- Clear approvals from the previous owner
  _approve(address0, tokenId);

  _balances[owner] = _balances[owner] - 1
  _owners[tokenId] = nil

  contract.event("transfer", owner, address0, tokenId)
end

--------------- Custom constructor ---------------------
--------------------------------------------------------
function constructor()
  _init('Query name at token origin', 'PEG')
end
--------------------------------------------------------

function mint(to, tokenId)
  assert(system.getSender() == system.getCreator(), "ARC2: mint - only contract creator can mint")
  _mint(to, tokenId)
end

function burn(tokenId)
  assert(_exists(tokenId), "ARC2: burn - nonexisting token")
  owner = ownerOf(tokenId)
  spender = system.getSender()
  assert(spender == owner or getApproved(tokenId) == spender or isApprovedForAll(owner, spender), "ARC2: burn - caller is not owner nor approved")

  _burn(tokenId)
end

-- Get a token name
-- @type    query
-- @return  (string) name of this token
function name()
  return _name:get()
end


-- Get a token symbol
-- @type    query
-- @return  (string) symbol of this token
function symbol()
  return _symbol:get()
end

-- Count of all NFTs assigned to an owner
-- @type    query
-- @param   owner  (address) a target address
-- @return  (ubig) the number of NFT tokens of owner
function balanceOf(owner)
  assert(owner ~= address0, "ARC2: balanceOf - query for zero address")
  return _balances[owner] or bignum.number(0)
end


-- Find the owner of an NFT
-- @type    query
-- @param   tokenId (str128) the NFT id
-- @return  (address) the address of the owner of the NFT
function ownerOf(tokenId) 
  owner = _owners[tokenId] or address0;
  assert(owner ~= address0, "ARC2: ownerOf - query for nonexistent token")
  return owner
end



-- Transfer a token of 'from' to 'to'
-- @type    call
-- @param   from    (address) a sender's address
-- @param   to      (address) a receiver's address
-- @param   tokenId (str128) the NFT token to send
-- @param   ...     (Optional) addtional data, MUST be sent unaltered in call to 'onARC2Received' on 'to'
-- @event   transfer(from, to, value)
function safeTransferFrom(from, to, tokenId, ...) 
  _typecheck(from, 'address')
  _typecheck(to, 'address')
  _typecheck(tokenId, 'str128')

  assert(_exists(tokenId), "ARC2: safeTransferFrom - nonexisting token")
  owner = ownerOf(tokenId)
  assert(owner == from, "ARC2: safeTransferFrom - transfer of token that is not own")
  assert(to ~= address0, "ARC2: safeTransferFrom - transfer to the zero address")

  spender = system.getSender()
  assert(spender == owner or getApproved(tokenId) == spender or isApprovedForAll(owner, spender), "ARC2: safeTransferFrom - caller is not owner nor approved")

  -- Clear approvals from the previous owner
  _approve(address0, tokenId)

  _balances[from] = _balances[from] - 1
  _balances[to] = (_balances[to] or bignum.number(0)) + 1
  _owners[tokenId] = to
  
  _callOnARC2Received(from, to, tokenId, ...)

  contract.event("transfer", from, to, tokenId)
end


-- Change or reaffirm the approved address for an NFT
-- @type    call
-- @param   to          (address) the new approved NFT controller
-- @param   tokenId     (str128) the NFT token to approve
-- @event   approve(owner, to, tokenId)
function approve(to, tokenId)
  _typecheck(to, 'address')
  _typecheck(tokenId, 'str128')

  owner = ownerOf(tokenId)
  assert(owner ~= to, "ARC2: approve - to current owner")
  assert(system.getSender() == owner or isApprovedForAll(owner, system.getSender()), 
    "ARC2: approve - caller is not owner nor approved for all")

  _approve(to, tokenId);
end

-- Get the approved address for a single NFT
-- @type    query
-- @param   tokenId  (str128) the NFT token to find the approved address for
-- @return  (address) the approved address for this NFT, or the zero address if there is none
function getApproved(tokenId) 
  _typecheck(tokenId, 'str128')
  assert(_exists(tokenId), "ARC2: getApproved - nonexisting token")

  return _tokenApprovals[tokenId] or address0;
end


-- Allow operator to control all sender's token
-- @type    call
-- @param   operator  (address) a operator's address
-- @param   approved  (boolean) true if the operator is approved, false to revoke approval
-- @event   approvalForAll(owner, operator, approved)
function setApprovalForAll(operator, approved) 
  _typecheck(operator, 'address')
  _typecheck(approved, 'boolean')

  assert(operator ~= system.getSender(), "ARC2: setApprovalForAll - to caller")
  _operatorApprovals[system.getSender() .. '/' .. operator] = approved

  contract.event("approvalForAll", system.getSender(), operator, approved)
end


-- Get allowance from owner to spender
-- @type    query
-- @param   owner       (address) owner's address
-- @param   operator    (address) allowed address
-- @return  (bool) true/false
function isApprovedForAll(owner, operator) 
  return _operatorApprovals[owner .. '/' .. operator] or false
end


abi.register(setApprovalForAll, safeTransferFrom, approve, mint, burn)
abi.register_view(name, symbol, balanceOf, ownerOf, getApproved, isApprovedForAll) 
]]

abi.register(verifyDepositProof, oracleUpdate, newAnchor, tAnchorUpdate, tFinalUpdate, unfreezeFeeUpdate, tokensReceived, mint, burn, unlock, unfreeze, mintARC2, onARC2Received)
abi.payable(freeze, default)
