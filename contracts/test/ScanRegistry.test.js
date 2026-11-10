// Acceptance tests for the optional ScanRegistry contract (PRD 15.5).
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { ethers } = require("hardhat");

const digestOf = (text) => "0x" + createHash("sha256").update(text).digest("hex");

async function expectRevert(promise, errorName) {
  try {
    await promise;
  } catch (err) {
    const text = `${err.message} ${err.shortMessage ?? ""} ${JSON.stringify(err.revert ?? {})}`;
    assert.ok(text.includes(errorName), `expected revert ${errorName}, got: ${err.message}`);
    return;
  }
  assert.fail(`expected revert ${errorName}`);
}

describe("ScanRegistry", function () {
  let registry, owner, publisher, outsider;
  const digest = digestOf('{"schema_version":"1","scan_id":"demo","status":"completed"}');

  beforeEach(async function () {
    [owner, publisher, outsider] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("ScanRegistry");
    registry = await Factory.deploy(publisher.address);
    await registry.waitForDeployment();
  });

  it("lets an authorized publisher register a digest and emits the event", async function () {
    const tx = await registry.connect(publisher).registerAttestation(digest);
    const receipt = await tx.wait();
    const block = await ethers.provider.getBlock(receipt.blockNumber);
    const log = registry.interface.parseLog(receipt.logs[0]);
    assert.equal(log.name, "AttestationRegistered");
    assert.equal(log.args.attestationDigest, digest);
    assert.equal(log.args.publisher, publisher.address);
    assert.equal(log.args.timestamp, BigInt(block.timestamp));
    assert.equal(await registry.isRegistered(digest), true);
    const [pub, ts] = await registry.getAttestation(digest);
    assert.equal(pub, publisher.address);
    assert.equal(ts, BigInt(block.timestamp));
  });

  it("rejects unauthorized publishers", async function () {
    await expectRevert(registry.connect(outsider).registerAttestation(digest), "NotPublisher");
    assert.equal(await registry.isRegistered(digest), false);
  });

  it("applies a deterministic duplicate rule (first registration is final)", async function () {
    await (await registry.connect(publisher).registerAttestation(digest)).wait();
    await registry.connect(owner).setPublisher(outsider.address, true);
    await expectRevert(registry.connect(outsider).registerAttestation(digest), "AlreadyRegistered");
    const [pub] = await registry.getAttestation(digest);
    assert.equal(pub, publisher.address);
  });

  it("rejects the zero digest", async function () {
    await expectRevert(registry.connect(publisher).registerAttestation(ethers.ZeroHash), "ZeroDigest");
  });

  it("only the owner manages publishers; revoked publishers cannot register", async function () {
    await expectRevert(registry.connect(outsider).setPublisher(outsider.address, true), "NotOwner");
    await registry.connect(owner).setPublisher(publisher.address, false);
    await expectRevert(registry.connect(publisher).registerAttestation(digest), "NotPublisher");
    await expectRevert(registry.connect(owner).setPublisher(ethers.ZeroAddress, true), "ZeroAddress");
  });

  it("uses two-step ownership transfer", async function () {
    await registry.connect(owner).transferOwnership(outsider.address);
    assert.equal(await registry.owner(), owner.address);
    await expectRevert(registry.connect(publisher).acceptOwnership(), "NotPendingOwner");
    await registry.connect(outsider).acceptOwnership();
    assert.equal(await registry.owner(), outsider.address);
    assert.equal(await registry.pendingOwner(), ethers.ZeroAddress);
  });

  it("sends only the 32-byte digest on-chain (no findings, paths or secrets)", async function () {
    const tx = await registry.connect(publisher).registerAttestation(digest);
    // calldata = 4-byte selector + one 32-byte word
    assert.equal(tx.data.length, 2 + 8 + 64);
    assert.equal(tx.data.slice(10), digest.slice(2));
    const receipt = await tx.wait();
    assert.equal(receipt.logs.length, 1);
    assert.equal(receipt.logs[0].data.length, 2 + 64); // only the timestamp word
  });

  it("unknown digests are reported as unregistered", async function () {
    const [pub, ts] = await registry.getAttestation(digestOf("other"));
    assert.equal(pub, ethers.ZeroAddress);
    assert.equal(ts, 0n);
  });
});
