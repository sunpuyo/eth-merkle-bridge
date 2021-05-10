// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol#08ba72afa27133be2c8d16ba6964d3024238b859";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/access/Ownable.sol#0db76e98f90550f1ebbb3dea71c7d12d5c533b5c";


contract MintableERC721 is ERC721, Ownable {
    
    constructor (string memory name, string memory symbol) ERC721(name, symbol) {
    }
    
    function mint(address to, uint256 tokenId) public virtual onlyOwner {
        _safeMint(to, tokenId);
    }
}