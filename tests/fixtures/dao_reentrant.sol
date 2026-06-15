// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// TheDAO-style reentrancy: external call before state update.
contract DAOReentrant {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerable: sends ETH before zeroing the balance, enabling reentrancy.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }
}
