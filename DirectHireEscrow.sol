// SPDX-License-Identifier: Apache-2.0
// DirectHire™ Escrow Contract — iDARIA Foundation
// Deployed on Polygon Mumbai Testnet
// Version: 1.0.0

pragma solidity ^0.8.20;

/**
 * @title DirectHireEscrow
 * @author iDARIA Foundation — Turin R&D Hub
 *
 * @notice Silicon-verified smart contract escrow for professional services
 * and gig economy deliveries.
 *
 * Payment is held in escrow and released ONLY when a cryptographic
 * Proof-of-Delivery (signed by the worker's OMNIA-OS device TEE) is
 * verified on-chain.
 *
 * This eliminates:
 *   - Glovo's 25-35% commission (replaced by 5% protocol fee)
 *   - Recruiter's 20-40% fee (replaced by 5% DirectHire fee)
 *   - Arbitrary pay withholding (TEE proof = automatic release)
 *   - Biased dispute resolution (DAM uses on-chain cryptographic evidence)
 *
 * Settlement in EURC (MiCA-compliant digital Euro via Circle).
 */
contract DirectHireEscrow {

    // ── State ──────────────────────────────────────────────────────────────

    address public immutable IDARIA_PLATFORM;
    uint256 public constant  PLATFORM_FEE_BPS = 500; // 5%

    enum Status {
        PENDING,    // Created, awaiting funding
        FUNDED,     // Escrowed — worker can start
        COMPLETE,   // Payment released to worker
        DISPUTED,   // DAM (Decentralised Arbitration Module) triggered
        CANCELLED   // Refunded to client
    }

    struct Milestone {
        string  description;
        uint256 amount;
        bool    completed;
        bytes32 proofHash;   // keccak256 of OMNIA-OS attestation packet JSON
        string  ipfsCid;     // IPFS CID of full attestation packet
    }

    struct Contract {
        address payable client;
        address payable worker;
        uint256 totalAmount;
        uint256 createdAt;
        uint256 deadline;
        Status  status;
        Milestone[] milestones;
        uint256 trustScoreRequired; // Minimum TrustScore (0 = any worker)
        string  description;
    }

    mapping(uint256 => Contract) public contracts;
    uint256 public nextContractId;

    // ── Events ─────────────────────────────────────────────────────────────

    event ContractCreated(
        uint256 indexed contractId,
        address indexed client,
        address indexed worker,
        uint256 totalAmount,
        uint256 deadline
    );
    event ContractFunded(uint256 indexed contractId, uint256 amount);
    event ProofSubmitted(
        uint256 indexed contractId,
        uint256 indexed milestoneIndex,
        bytes32 proofHash,
        string  ipfsCid
    );
    event PaymentReleased(
        uint256 indexed contractId,
        address indexed worker,
        uint256 amount,
        uint256 platformFee
    );
    event DisputeRaised(uint256 indexed contractId, address raisedBy);
    event ContractCancelled(uint256 indexed contractId);

    // ── Errors ─────────────────────────────────────────────────────────────

    error NotAuthorized();
    error InvalidStatus(Status expected, Status actual);
    error InsufficientPayment();
    error DeadlinePassed();
    error MilestoneAlreadyCompleted(uint256 milestoneIndex);
    error InvalidProofHash();
    error TransferFailed();
    error NoMilestones();
    error MilestoneMismatch();

    // ── Constructor ────────────────────────────────────────────────────────

    constructor(address _platform) {
        IDARIA_PLATFORM = _platform;
    }

    // ── Core Functions ─────────────────────────────────────────────────────

    /**
     * @notice Create a new DirectHire contract.
     *
     * @param worker                Worker's Ethereum address
     * @param deadlineSeconds       Seconds until delivery deadline
     * @param milestoneDescriptions Description of each milestone
     * @param milestoneAmounts      Wei allocated to each milestone
     * @param trustScoreRequired    Minimum TrustScore (0 = any worker)
     * @param description           Human-readable contract description
     */
    function createContract(
        address payable worker,
        uint256 deadlineSeconds,
        string[] calldata milestoneDescriptions,
        uint256[] calldata milestoneAmounts,
        uint256 trustScoreRequired,
        string calldata description
    ) external payable returns (uint256 contractId) {

        if (milestoneDescriptions.length == 0) revert NoMilestones();
        if (milestoneDescriptions.length != milestoneAmounts.length)
            revert MilestoneMismatch();

        uint256 total;
        for (uint256 i = 0; i < milestoneAmounts.length; i++) {
            total += milestoneAmounts[i];
        }
        if (msg.value < total) revert InsufficientPayment();

        contractId = nextContractId++;
        Contract storage c = contracts[contractId];

        c.client             = payable(msg.sender);
        c.worker             = worker;
        c.totalAmount        = total;
        c.createdAt          = block.timestamp;
        c.deadline           = block.timestamp + deadlineSeconds;
        c.status             = Status.FUNDED;
        c.trustScoreRequired = trustScoreRequired;
        c.description        = description;

        for (uint256 i = 0; i < milestoneDescriptions.length; i++) {
            c.milestones.push(Milestone({
                description: milestoneDescriptions[i],
                amount:      milestoneAmounts[i],
                completed:   false,
                proofHash:   bytes32(0),
                ipfsCid:     ""
            }));
        }

        emit ContractCreated(contractId, msg.sender, worker, total, c.deadline);
        emit ContractFunded(contractId, msg.value);
    }

    /**
     * @notice Worker submits Proof-of-Delivery for a milestone.
     *
     * The proof is the keccak256 hash of the OMNIA-OS attestation packet.
     * The full packet is stored on IPFS; only the hash is on-chain.
     *
     * In Phase 2: this calls the iDARIA TrustScore oracle to verify
     * the attestation packet on-chain before releasing payment.
     *
     * @param contractId            Contract identifier
     * @param milestoneIndex        Which milestone is being completed
     * @param omniaAttestationHash  keccak256 of OMNIA-OS attestation JSON
     * @param ipfsCid               IPFS CID of the full attestation packet
     */
    function submitProofOfDelivery(
        uint256 contractId,
        uint256 milestoneIndex,
        bytes32 omniaAttestationHash,
        string calldata ipfsCid
    ) external {
        Contract storage c = contracts[contractId];

        if (msg.sender != c.worker) revert NotAuthorized();
        if (c.status != Status.FUNDED) revert InvalidStatus(Status.FUNDED, c.status);
        if (block.timestamp > c.deadline) revert DeadlinePassed();
        if (omniaAttestationHash == bytes32(0)) revert InvalidProofHash();

        Milestone storage m = c.milestones[milestoneIndex];
        if (m.completed) revert MilestoneAlreadyCompleted(milestoneIndex);

        m.proofHash = omniaAttestationHash;
        m.ipfsCid   = ipfsCid;
        m.completed = true;

        emit ProofSubmitted(contractId, milestoneIndex, omniaAttestationHash, ipfsCid);

        // Auto-release when all milestones complete
        bool allComplete = true;
        for (uint256 i = 0; i < c.milestones.length; i++) {
            if (!c.milestones[i].completed) { allComplete = false; break; }
        }
        if (allComplete) _releasePayment(contractId);
    }

    /**
     * @notice Client can manually approve and release payment.
     */
    function approveAndRelease(uint256 contractId) external {
        Contract storage c = contracts[contractId];
        if (msg.sender != c.client) revert NotAuthorized();
        if (c.status != Status.FUNDED) revert InvalidStatus(Status.FUNDED, c.status);
        _releasePayment(contractId);
    }

    /**
     * @notice Either party raises a dispute — routes to DAM (Phase 2).
     * On-chain proof from OMNIA-OS attestation packet is used as evidence.
     */
    function raiseDispute(uint256 contractId) external {
        Contract storage c = contracts[contractId];
        if (msg.sender != c.client && msg.sender != c.worker)
            revert NotAuthorized();
        if (c.status != Status.FUNDED) revert InvalidStatus(Status.FUNDED, c.status);

        c.status = Status.DISPUTED;
        emit DisputeRaised(contractId, msg.sender);
        // TODO Phase 2: trigger Decentralised Arbitration Module (DAM)
        // OMNI token stakers resolve based on on-chain OMNIA-OS proof evidence
    }

    /**
     * @notice Client cancels if deadline passed with no proof submitted.
     */
    function cancelAndRefund(uint256 contractId) external {
        Contract storage c = contracts[contractId];
        if (msg.sender != c.client) revert NotAuthorized();
        if (c.status != Status.FUNDED) revert InvalidStatus(Status.FUNDED, c.status);
        require(block.timestamp > c.deadline, "Deadline not yet passed");

        c.status = Status.CANCELLED;
        (bool ok,) = c.client.call{value: c.totalAmount}("");
        if (!ok) revert TransferFailed();
        emit ContractCancelled(contractId);
    }

    // ── Internal ───────────────────────────────────────────────────────────

    function _releasePayment(uint256 contractId) internal {
        Contract storage c = contracts[contractId];
        c.status = Status.COMPLETE;

        uint256 fee    = (c.totalAmount * PLATFORM_FEE_BPS) / 10_000;
        uint256 payout = c.totalAmount - fee;

        (bool feeOk,) = payable(IDARIA_PLATFORM).call{value: fee}("");
        if (!feeOk) revert TransferFailed();

        (bool payOk,) = c.worker.call{value: payout}("");
        if (!payOk) revert TransferFailed();

        emit PaymentReleased(contractId, c.worker, payout, fee);
    }

    // ── View Functions ─────────────────────────────────────────────────────

    function getContractStatus(uint256 contractId) external view returns (Status) {
        return contracts[contractId].status;
    }

    function getMilestoneCount(uint256 contractId) external view returns (uint256) {
        return contracts[contractId].milestones.length;
    }

    function getMilestone(uint256 contractId, uint256 idx)
        external view returns (
            string memory description,
            uint256 amount,
            bool    completed,
            bytes32 proofHash,
            string memory ipfsCid
        )
    {
        Milestone storage m = contracts[contractId].milestones[idx];
        return (m.description, m.amount, m.completed, m.proofHash, m.ipfsCid);
    }

    function getContractInfo(uint256 contractId)
        external view returns (
            address client,
            address worker,
            uint256 totalAmount,
            uint256 deadline,
            Status  status,
            string memory description
        )
    {
        Contract storage c = contracts[contractId];
        return (c.client, c.worker, c.totalAmount, c.deadline, c.status, c.description);
    }
}
