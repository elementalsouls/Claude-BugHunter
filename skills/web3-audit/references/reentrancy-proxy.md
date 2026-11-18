# Reentrancy / Flash Loan / Signature / Proxy

> Reference content for the `web3-audit` skill. Originally bug classes 7–10 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## 7. REENTRANCY
> 2016–present. CEI pattern prevents it. Still found in DeFi.

### Variants
- **Single-function**: attacker re-enters same function before state updated
- **Cross-function**: re-enters a sibling function with stale state
- **Cross-contract**: re-enters via a callback to another protocol
- **Read-only**: re-enters a view function that returns stale data used by attacker

### Root Cause Pattern
```solidity
// VULNERABLE (effects after interaction):
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}("");  // INTERACTION first
    require(success);
    balances[msg.sender] -= amount;  // EFFECT after → reentrancy window
}

// CORRECT (CEI — Checks, Effects, Interactions):
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);  // CHECK
    balances[msg.sender] -= amount;            // EFFECT
    (bool success,) = msg.sender.call{value: amount}("");  // INTERACTION last
    require(success);
}
```

### Grep Patterns
```bash
# External calls before state updates
grep -rn "\.call{value\|safeTransfer\|transfer(" contracts/ -B10 | grep -v "require\|revert"

# Missing nonReentrant modifier on critical functions
grep -rn "function withdraw\|function redeem\|function claim" contracts/ -A2 | grep -v "nonReentrant"

# Storage slot for reentrancy guard
grep -rn "nonReentrant\|ReentrancyGuard\|_notEntered" contracts/
```

---

## 8. FLASH LOAN ATTACKS

### Oracle Manipulation via Flash Loan
```solidity
// Attack flow:
// 1. Borrow $100M from Aave flash loan
// 2. Dump token in Uniswap pool → crash spot price
// 3. Protocol reads Uniswap spot → undercollateralized loans accepted
// 4. Borrow max against cheap collateral
// 5. Repay flash loan, keep profits
```

### Price Oracle Sanity Checks (what to look for)
```bash
grep -rn "getReserves\|getAmountsOut\|slot0\b" contracts/ -A5
# spot price from reserves = manipulatable with flash loan
# slot0 = Uniswap V3 spot price = manipulatable
```

---

## 9. SIGNATURE REPLAY

### Missing Nonce
```solidity
// VULNERABLE:
function permit(address owner, address spender, uint256 value,
                uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    bytes32 hash = keccak256(abi.encodePacked(owner, spender, value, deadline));
    // MISSING: nonce not included → same signature usable multiple times
    require(ecrecover(hash, v, r, s) == owner);
}
```

### Missing Chain ID
```solidity
// VULNERABLE: signature valid on mainnet AND testnet AND all forks
bytes32 hash = keccak256(abi.encodePacked(params));
// MISSING: block.chainid not in hash → works on any chain
```

### Grep Patterns
```bash
grep -rn "ecrecover\|ECDSA\.recover" contracts/ -B20
# Check: does the signed hash include nonce + chainId + contract address?

grep -rn "nonce\|_nonces\|nonces\[" contracts/
```

---

## 10. PROXY / UPGRADE ISSUES

### Storage Collision
```solidity
// Implementation and proxy share storage layout
// Proxy slot 0: _owner
// Implementation slot 0: _initialized
// → writing to _initialized overwrites _owner
```

### Uninitialized Implementation
```solidity
// If implementation can be initialized directly → anyone becomes owner of implementation
// Attack: call initialize() on implementation contract → call upgradeTo() → replace logic
```

### delegatecall to User-Controlled Address
```solidity
function execute(address target, bytes calldata data) external onlyOwner {
    target.delegatecall(data);  // target is validated, but what if owner is compromised?
}
```

### Grep Patterns
```bash
# UUPS initialization protection
grep -rn "function initialize\b\|_disableInitializers\|initializer" contracts/

# Delegate call
grep -rn "delegatecall\b" contracts/ -B3 -A5

# Storage layout — proxy uses EIP-1967 slots?
grep -rn "0x360894\|EIP1967\|_IMPLEMENTATION_SLOT" contracts/
```

---
