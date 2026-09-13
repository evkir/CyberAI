// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Base {
    address public owner;
    uint256 internal fee_;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setFee(uint256 fee) external onlyOwner {
        fee_ = fee;
    }
}

contract VaultV1 is Base {
    mapping(address => uint256) public balances;

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
    }
}

contract VaultV2 is Base {
    address public treasury;

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function sweep(address token) external onlyOwner {
        treasury = token;
    }
}
