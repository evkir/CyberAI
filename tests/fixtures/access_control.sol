// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Deliberately vulnerable access-control fixture.
contract Vault {
    address public owner;
    mapping(bytes32 => mapping(address => bool)) public roles;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // VULN: unprotected ownership takeover.
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    // VULN: unprotected initializer (re-runnable).
    function initialize(address admin) public {
        owner = admin;
    }

    // VULN: caller-controlled delegatecall.
    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "call failed");
    }

    // VULN: unprotected privileged mint -> High.
    function mint(address to, uint256 amount) external {
        roles[keccak256("MINTER")][to] = true;
    }

    // SAFE: guarded by modifier.
    function withdrawAll() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    // SAFE: guarded by inline check.
    function setFeeGuarded(uint256 fee) external {
        require(msg.sender == owner, "not owner");
    }

    // SAFE: not privileged, user deposit.
    function deposit() external payable {}

    // SAFE: view.
    function getOwner() external view returns (address) {
        return owner;
    }
}
