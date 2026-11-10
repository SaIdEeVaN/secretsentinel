// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @title ScanRegistry
/// @notice Anchors SHA-256 digests of SIGNED, NON-SENSITIVE SecretSentinel scan
///         attestations (PRD section 15). Development/demo target: Sepolia only.
/// @dev Stores ONLY a bytes32 digest, the publishing address and a timestamp.
///      Never secrets, findings, file paths, repository names or personal data.
///      A registration proves WHO published a digest and WHEN. It does NOT prove
///      that the attested scan was accurate or that any code is secure.
contract ScanRegistry {
    struct Record {
        address publisher;
        uint64 timestamp;
    }

    address public owner;
    address public pendingOwner;
    mapping(address => bool) public isPublisher;
    mapping(bytes32 => Record) private _records;

    event AttestationRegistered(bytes32 indexed attestationDigest, address indexed publisher, uint256 timestamp);
    event PublisherUpdated(address indexed publisher, bool allowed);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotPendingOwner();
    error NotPublisher();
    error ZeroAddress();
    error ZeroDigest();
    error AlreadyRegistered(bytes32 attestationDigest);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @param initialPublisher optional first approved publisher (address(0) for none)
    constructor(address initialPublisher) {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
        if (initialPublisher != address(0)) {
            isPublisher[initialPublisher] = true;
            emit PublisherUpdated(initialPublisher, true);
        }
    }

    /// @notice Approve or revoke a publisher. Use a dedicated publishing key,
    ///         never an application or treasury wallet.
    function setPublisher(address publisher, bool allowed) external onlyOwner {
        if (publisher == address(0)) revert ZeroAddress();
        isPublisher[publisher] = allowed;
        emit PublisherUpdated(publisher, allowed);
    }

    /// @notice Two-step ownership transfer to avoid locking the registry by typo.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        emit OwnershipTransferred(owner, msg.sender);
        owner = msg.sender;
        pendingOwner = address(0);
    }

    /// @notice Register an attestation digest. Duplicate digests are rejected
    ///         (deterministic replay rule): the first registration is final.
    function registerAttestation(bytes32 attestationDigest) external {
        if (!isPublisher[msg.sender]) revert NotPublisher();
        if (attestationDigest == bytes32(0)) revert ZeroDigest();
        if (_records[attestationDigest].publisher != address(0)) revert AlreadyRegistered(attestationDigest);
        _records[attestationDigest] = Record({publisher: msg.sender, timestamp: uint64(block.timestamp)});
        emit AttestationRegistered(attestationDigest, msg.sender, block.timestamp);
    }

    function isRegistered(bytes32 attestationDigest) external view returns (bool) {
        return _records[attestationDigest].publisher != address(0);
    }

    /// @return publisher address that registered the digest (zero if none)
    /// @return timestamp block timestamp of registration (zero if none)
    function getAttestation(bytes32 attestationDigest) external view returns (address publisher, uint256 timestamp) {
        Record memory r = _records[attestationDigest];
        return (r.publisher, r.timestamp);
    }
}
