pragma solidity ^0.8.0;

import "github.com/OpenZeppelin/openzeppelin-contracts/blob/5cd86f740d9a4b351cad196e7957a7d0406e7368/contracts/token/ERC20/ERC20.sol";

contract MintedERC20 is ERC20 {

    address creator;
    
    constructor(string memory tokenOrigin) ERC20(tokenOrigin, "PEG") {
        creator = msg.sender;
    }

    modifier onlyCreator() {
        require(msg.sender == creator, "Only creator can mint");
        _;
    }

    function mint(address receiver, uint amount) public onlyCreator returns (bool) {
        _mint(receiver, amount);
        return true;
    }

    function burn(address account, uint amount) public onlyCreator returns (bool) {
        _burn(account, amount);
        return true;
    }

}