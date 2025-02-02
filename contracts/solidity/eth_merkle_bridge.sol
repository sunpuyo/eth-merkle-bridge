pragma solidity ^0.5.10;

import "./minted_erc20.sol";

import "./IERC721.sol";
import "./IERC721Receiver.sol";

contract EthMerkleBridge is IERC721Receiver, IERC165 {
    // Trie root of the opposit side bridge contract. Mints and Unlocks require a merkle proof
    // of state inclusion in this last Root.
    bytes32 public _anchorRoot;
    // Height of the last block anchored
    uint public _anchorHeight;
    // _tAnchor is the anchoring periode of the bridge
    uint public _tAnchor;
    // _tFinal is the time after which the bridge operator consideres a block finalised
    // this value is only useful if the anchored chain doesn't have LIB
    // Since Aergo has LIB it is a simple indicator for wallets.
    uint public _tFinal;
    // address that controls anchoring and settings of the bridge
    address public _oracle;

    // Registers locked balances per account reference: user provides merkle proof of locked balance
    mapping(bytes => uint) public _locks;
    // Registers unlocked balances per account reference: prevents unlocking more than was burnt
    mapping(bytes => uint) public _unlocks;
    // Registers burnt balances per account reference : user provides merkle proof of burnt balance
    mapping(bytes => uint) public _burns;
    // Registers minted balances per account reference : prevents minting more than what was locked
    mapping(bytes => uint) public _mints;
    // Registers locked token's block number per account reference: user provides merkle proof
    mapping(bytes => uint) public _locksERC721;
    // Registers unlocked token's the locked block number per account reference : user provides merkle proof
    mapping(bytes => uint) public _unlocksERC721;

    // _bridgeTokens keeps track of tokens that were received through the bridge
    mapping(string => MintedERC20) public _bridgeTokens;
    // _mintedTokens is the same as _bridgeTokens but keys and values are swapped
    // _mintedTokens is used for preventing a minted token from being locked instead of burnt.
    mapping(address => string) public _mintedTokens;

    event newMintedERC20(string indexed origin, MintedERC20 indexed addr);
    event lockEvent(address indexed sender, IERC20 indexed tokenAddress, string indexed receiver, uint amount);
    event unlockEvent(address indexed sender, IERC20 indexed tokenAddress, address indexed receiver, uint amount);
    event lockERC721Event(address indexed sender, address indexed tokenAddress, string receiver, uint tokenId, uint blockNumber);
    event unlockERC721Event(address indexed sender, address indexed tokenAddress, address receiver, uint tokenId, uint blockNumber);
    event mintEvent(address indexed sender, MintedERC20 indexed tokenAddress, address indexed receiver, uint amount);
    event burnEvent(address indexed sender, MintedERC20 indexed tokenAddress, string indexed receiver, uint amount);
    event anchorEvent(address indexed sender, bytes32 root, uint height);
    event newTAnchorEvent(address indexed sender, uint tAnchor);
    event newTFinalEvent(address indexed sender, uint tFinal);
    event newOracleEvent(address indexed sender, address newOracle);

    constructor(
        uint tAnchor,
        uint tFinal
    ) public {
        _tAnchor = tAnchor;
        _tFinal = tFinal;
        // the oracle is set to the sender who must transfer ownership to oracle contract
        // with oracleUpdate(), once deployed
        _oracle = msg.sender;
    }

    bytes4 private constant _INTERFACE_ID_ERC721 = 0x80ac58cd;
    bytes4 private constant _INTERFACE_ID_ERC165 = 0x01ffc9a7;

    function supportsInterface(bytes4 interfaceId) external view returns (bool) {
        return interfaceId == _INTERFACE_ID_ERC721
            || interfaceId == _INTERFACE_ID_ERC165;
    }

    // Throws if called by any account other than the owner.
    modifier onlyOracle() {
        require(msg.sender == _oracle, "Only oracle can call");
        _;
    }

    // Change the current oracle contract
    // @param   newOracle - address of new oracle
    function oracleUpdate(
        address newOracle
    ) public onlyOracle {
        require(newOracle != address(0), "Don't burn the oracle");
        _oracle = newOracle;
        emit newOracleEvent(msg.sender, newOracle);
    }

    // Register new anchoring periode
    // @param   tAnchor - new anchoring periode
    function tAnchorUpdate(
        uint tAnchor
    ) public onlyOracle {
        _tAnchor = tAnchor;
        emit newTAnchorEvent(msg.sender, tAnchor);
    }

    // Register new finality of anchored chain
    // @param   tFinal - new finality of anchored chain
    function tFinalUpdate(
        uint tFinal
    ) public onlyOracle {
        _tFinal = tFinal;
        emit newTFinalEvent(msg.sender, tFinal);
    }

    // Register a new anchor
    // @param   root - Aergo storage root
    // @param   height - block height of root
    function newAnchor(
        bytes32 root,
        uint height
    ) public onlyOracle {
        require(height > _anchorHeight + _tAnchor, "Next anchor height not reached");
        _anchorRoot = root;
        _anchorHeight = height;
        emit anchorEvent(msg.sender, root, height);
    }


    // lock tokens in the bridge contract
    // @param   token - token locked to transfer
    // @param   amount - amount of tokens to send
    // @param   receiver - Aergo address receiver accross the bridge
    function lock(
        IERC20 token,
        uint amount,
        string memory receiver
    ) public returns (bool) {
        string memory addr = _mintedTokens[address(token)];
        require(bytes(addr).length == 0, "cannot lock token that was minted by bridge, must be burnt");
        // Add locked amount to total
        bytes memory accountRef = abi.encodePacked(receiver, token);
        _locks[accountRef] += amount;
        require(_locks[accountRef] >= amount, "total _locks overflow");
        // Pull token from owner to bridge contract (owner must set approval before calling lock)
        // using msg.sender, the owner must call lock, but we can make delegated transfers with sender
        // address as parameter.
        require(token.transferFrom(msg.sender, address(this), amount), "Failed to lock");
        emit lockEvent(msg.sender, token, receiver, amount);
        return true;
    }

    // unlock tokens burnt on Aergo
    // anybody can unlock, the receiver is the account who's burnt balance is recorded
    // @param   receiver - address of receiver
    // @param   balance - total balance of tokens burnt on Aergo
    // @param   token - address of token to unlock
    // @param   mp - merkle proof of inclusion of burnt balance on Aergo
    // @param   bitmap - bitmap of non default nodes in the merkle proof
    // @param   leafHeight - height of leaf containing the value in the state SMT
    function unlock(
        address receiver,
        uint balance,
        IERC20 token,
        bytes32[] memory mp, // bytes[] is not yet supported so we use a bitmap of proof elements
        bytes32 bitmap,
        uint8 leafHeight
    ) public returns(bool) {
        require(balance>0, "Balance must be positive");
        bytes memory accountRef = abi.encodePacked(receiver, address(token));
        require(verifyDepositProof("_sv__burns-", accountRef, balance, mp, bitmap, leafHeight), "Failed to verify lock proof");
        uint unlockedSoFar = _unlocks[accountRef];
        uint amountToTransfer = balance - unlockedSoFar;
        require(amountToTransfer>0, "Burn tokens before unlocking");
        _unlocks[accountRef] = balance;
        require(token.transfer(receiver, amountToTransfer), "Failed to transfer unlock");
        emit unlockEvent(msg.sender, token, receiver, amountToTransfer);
        return true;
    }

    // implementation of IERC721Receiver
    // lock ERC721 token to bridge contract
    // @param   receiverAergoAddress - receiving aergo address
    function onERC721Received(address operator, address from, uint256 tokenId, bytes memory receiverAergoAddress) public returns (bytes4) {
        require(receiverAergoAddress.length == 52, "Invalid Aergo address length (must be 52)");
        require(receiverAergoAddress[0] == bytes1('A'), "Invalid Aergo adress (must start with A)");

        string memory receiverStr = string(receiverAergoAddress);
        // Record block number
        bytes memory accountRef = abi.encodePacked(receiverStr, uintToString(tokenId), msg.sender);
        _locksERC721[accountRef] = block.number;
        
        emit lockERC721Event(from, msg.sender, receiverStr, tokenId, block.number); //TODO check erc721 address and data (receiver address)

        return this.onERC721Received.selector;
    }


    // unlock ERC721 NFT burnt on Aergo
    // anybody can unlock, the receiver is the account who's burnt balance is recorded
    // @param   receiver - address of receiver
    // @param   tokenId - NFT id
    // @param   burnARC2BlockNum - the block number of the tx that sends ARC2 to the Aergo Merkle Bridge
    // @param   token - address of ERC721 token to unlock
    // @param   mp - merkle proof of inclusion of burnt balance on Aergo
    // @param   bitmap - bitmap of non default nodes in the merkle proof
    // @param   leafHeight - height of leaf containing the value in the state SMT
    function unlockERC721(
        address receiver,
        uint tokenId,
        uint burnARC2BlockNum,
        IERC721 token,
        bytes32[] memory mp, // bytes[] is not yet supported so we use a bitmap of proof elements
        bytes32 bitmap,
        uint8 leafHeight
    ) public returns(bool) {
        
        bytes memory accountRef = abi.encodePacked(receiver, uintToString(tokenId), address(token));
        require(_unlocksERC721[accountRef] != burnARC2BlockNum, "Already unlocked token");
        require(verifyDepositProof("_sv__burnsARC2-", accountRef, burnARC2BlockNum, mp, bitmap, leafHeight), "Failed to verify lock proof");

        _unlocksERC721[accountRef] = burnARC2BlockNum;
        token.safeTransferFrom(address(this), receiver, tokenId);
        emit unlockERC721Event(msg.sender, address(token), receiver, tokenId, burnARC2BlockNum);

        return true;
    }

    // mint a token locked on Aergo
    // anybody can mint, the receiver is the account who's locked balance is recorded
    // @param   receiver - address of receiver
    // @param   balance - total balance of tokens locked on Aergo
    // @param   tokenOrigin - Aergo address of token locked
    // @param   mp - merkle proof of inclusion of locked balance on Aergo
    // @param   bitmap - bitmap of non default nodes in the merkle proof
    // @param   leafHeight - height of leaf containing the value in the state SMT
    function mint(
        address receiver,
        uint balance,
        string memory tokenOrigin,
        bytes32[] memory mp, // bytes[] is not yet supported so we use a bitmap of proof elements
        bytes32 bitmap,
        uint8 leafHeight
    ) public returns(bool) {
        require(balance>0, "Balance must be positive");
        bytes memory accountRef = abi.encodePacked(receiver, tokenOrigin);
        require(verifyDepositProof("_sv__locks-", accountRef, balance, mp, bitmap, leafHeight), "Failed to verify lock proof");
        uint mintedSoFar = _mints[accountRef];
        uint amountToTransfer = balance - mintedSoFar;
        require(amountToTransfer>0, "Lock tokens before minting");
        MintedERC20 mintAddress = _bridgeTokens[tokenOrigin];
        if (mintAddress == MintedERC20(0)) {
            // first time bridging this token
            mintAddress = new MintedERC20(tokenOrigin);
            _bridgeTokens[tokenOrigin] = mintAddress;
            _mintedTokens[address(mintAddress)] = tokenOrigin;
            emit newMintedERC20(tokenOrigin, mintAddress);
        }
        _mints[accountRef] = balance;
        require(mintAddress.mint(receiver, amountToTransfer), "Failed to mint");
        emit mintEvent(msg.sender, mintAddress, receiver, amountToTransfer);
        return true;
    }

    // burn a pegged token
    // @param   receiver - Aergo address
    // @param   amount - number of tokens to burn
    // @param   mintAddress - address of pegged token to burn
    function burn(
        string memory receiver,
        uint amount,
        MintedERC20 mintAddress
    ) public returns (bool) {
        string memory originAddress = _mintedTokens[address(mintAddress)];
        require(bytes(originAddress).length != 0, "cannot burn token : must have been minted by bridge");
        // Add burnt amount to total
        bytes memory accountRef = abi.encodePacked(receiver, originAddress);
        _burns[accountRef] += amount;
        require(_burns[accountRef] >= amount, "total _burns overflow");
        // Burn token
        require(mintAddress.burn(msg.sender, amount), "Failed to burn");
        emit burnEvent(msg.sender, mintAddress, receiver, amount);
        return true;
    }

    // Aergo State Trie Merkle proof verification
    // @param   mapName - name of Lua map variable storing locked/burnt balances
    // @param   accountRef - key in mapName to record an account's token balance
    // @param   balance - balance recorded in accountRef of mapName
    // @param   mp - merkle proof of inclusion of accountRef, balance in _anchorRoot
    // @param   bitmap - bitmap of non default nodes in the merkle proof
    // @param   leafHeight - height of leaf containing the value in the state SMT
    function verifyDepositProof(
        string memory mapName,
        bytes memory accountRef,
        uint balance,
        bytes32[] memory mp, // bytes[] is not yet supported so we use a bitmap of proof elements
        bytes32 bitmap,
        uint8 leafHeight
    ) public view returns(bool) {
        bytes32 trieKey = sha256(abi.encodePacked(mapName, accountRef));
        bytes32 trieValue = sha256(abi.encodePacked("\"", uintToString(balance), "\""));
        bytes32 nodeHash = sha256(abi.encodePacked(trieKey, trieValue, uint8(256-leafHeight)));
        uint proofIndex = 0;
        for (uint8 i = leafHeight; i>0; i--){
            if (bitIsSet(bitmap, leafHeight-i)) {
                if (bitIsSet(trieKey, i-1)) {
                    nodeHash = sha256(abi.encodePacked(mp[proofIndex], nodeHash));
                } else {
                    nodeHash = sha256(abi.encodePacked(nodeHash, mp[proofIndex]));
                }
                proofIndex++;
            } else {
                if (bitIsSet(trieKey, i-1)) {
                    nodeHash = sha256(abi.encodePacked(byte(0x00), nodeHash));
                } else {
                    nodeHash = sha256(abi.encodePacked(nodeHash, byte(0x00)));
                }
            }
        }
        return _anchorRoot == nodeHash;
    }

    // check if the ith bit is set in bytes
    // @param   bits - bytesin which we check the ith bit
    // @param   i - index of bit to check
    function bitIsSet(bytes32 bits, uint8 i) public pure returns (bool) {
        return bits[i/8]&bytes1(uint8(1)<<uint8(7-i%8)) != 0;
    }

    // Lua contracts don't store real bytes of uint so converting to string in necessary
    // @param   num - convert uint to string type : 1234 -> "1234"
    function uintToString(uint num) public pure returns(string memory) {
        // https://github.com/oraclize/ethereum-api/blob/6fb6e887e7b95c496fd723a7c62ce40551f8028a/oraclizeAPI_0.5.sol#L1041
        if (num == 0) {
            return "0";
        }
        uint j = num;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len - 1;
        while (num != 0) {
            bstr[k--] = byte(uint8(48 + num % 10));
            num /= 10;
        }
        return string(bstr);
    }
}