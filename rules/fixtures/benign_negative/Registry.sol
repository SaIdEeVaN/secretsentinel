// SPDX-License-Identifier: MIT
// BENIGN FIXTURE: addresses, role identifiers and storage slots are public data.
pragma solidity ^0.8.24;

contract Registry {
    address public constant OWNER = 0x61acfc6f54696fc3efc67129593b7d42244c8307;
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x0d2038cf74fe94058f40132a46d59f3a00fe1a4c4f7e1afbb1ba2f740ce5273f;
    bytes32 public merkleRoot = 0xdbf0cc3907a930c9fbd99db0baeacd11a41501c4478854b3a07c60d77405ec2d;
}
