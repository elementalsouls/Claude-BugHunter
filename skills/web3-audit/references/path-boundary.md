# Incomplete Path / Off-by-One

> Reference content for the `web3-audit` skill. Originally bug classes 3–4 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## 3. INCOMPLETE CODE PATH
> #3 Critical — 17% of Criticals.

### The Function Family Comparison Test
```
1. List all state changes in function A (deposit/place/create)
2. List all state changes in function B (withdraw/update/cancel)
3. For each state change in A: does B have the corresponding reverse?
4. For each token transfer in A: does B have the corresponding refund?
If A does X but B doesn't do the reverse of X → BUG.
```

### Variant 1: Update Function Missing Refund (ThunderNFT)
```solidity
function place_order(OrderInput calldata order) external {
    token.safeTransferFrom(msg.sender, address(this), order.price);  // takes tokens
    orders[orderId] = order;
}
function update_order(OrderInput calldata updatedOrder) external {
    // BUG: NO REFUND for sell orders when price decreases → tokens permanently stuck
    orders[orderId] = updatedOrder;
}
```

### Variant 2: Partial Fill Token Stuck (Plume)
```solidity
function swapForETH(uint256 amountIn) external {
    token.safeTransferFrom(msg.sender, address(this), amountIn);
    uint256 filled = dex.swap(amountIn);  // partial fill possible
    _refundExcessEth(amountIn - filled);  // BUG: refunds ETH only, not ERC20
}
```

### Variant 3: mint() Bypasses Check That deposit() Has (MetaPool)
```solidity
function deposit(uint256 assets, address receiver) public override {
    shares = _deposit(assets, receiver);  // includes receipt validation
}
function mint(uint256 shares, address receiver) public override {
    assets = convertToAssets(shares);
    _mint(receiver, shares);  // MISSING: _deposit() validation → mints without receiving assets
}
```

### Grep Patterns
```bash
grep -rn "function place_\|function create_\|function add_\|function open_" contracts/ -A5
grep -rn "function update_\|function modify_\|function cancel_" contracts/ -A5
grep -rn "safeApprove\b" contracts/    # safeApprove without zero-reset before
grep -rn "delete\b" contracts/ -B5 -A5  # delete before operation completes
grep -rn "function deposit\|function mint\|function withdraw\|function redeem" contracts/ -A10
```

---

## 4. OFF-BY-ONE & BOUNDARY CONDITIONS
> #4 High — 22% of Highs. Single character change. Massive impact.

### Root Cause
```solidity
// VeChain Stargate — post-exit reward drain:
function _claimableDelegationPeriods(address delegator) internal view returns (uint256) {
    if (endPeriod > nextClaimablePeriod) {  // BUG: should be >=
        return 0;  // exited users get nothing
    }
    return nextClaimablePeriod - lastClaimedPeriod;  // rewards for period AFTER exit
}
```

### Mental Test for Every Comparison
> For every `if (A > B)`: "What happens when A == B?" Is that correct?

### 6 Boundary Locations to Check
1. Period/Epoch boundaries: `>` vs `>=` at period end
2. Time-based locks: does `block.timestamp == deadline` lock or unlock?
3. Loop break conditions: `break` with `>` vs `>=`
4. Array index boundaries: `i <= array.length` (should be `i < array.length`)
5. Amount/balance boundaries: `>= amount` allows exact full withdrawal?
6. Rounding/precision: can any input produce 0 output that should be non-zero?

### Grep Patterns
```bash
# Boundaries in comparisons
grep -rn "Period\|Epoch\|Round\|Deadline\|period\|epoch\|deadline" contracts/ -A3 | grep "[<>][^=]"

# Loop breaks
grep -rn "\bbreak\b" contracts/ -B10

# Off-by-one in array access
grep -rn "\.length\s*-\s*1\|i\s*<=\s*.*\.length\b" contracts/
```

---
