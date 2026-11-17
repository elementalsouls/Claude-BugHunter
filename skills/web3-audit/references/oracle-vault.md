# Oracle / ERC4626

> Reference content for the `web3-audit` skill. Originally bug classes 5–6 of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## 5. ORACLE / PRICE MANIPULATION
> 12% of all reports. Largest individual payouts. $117M Mango, $70M Curve.

### Bug A: Missing Staleness Check (most common)
```solidity
// VULNERABLE:
(, int256 price,,,) = priceFeed.latestRoundData();
return uint256(price);  // If Chainlink node goes down, stale price returned indefinitely

// CORRECT:
(, int256 price,, uint256 updatedAt,) = priceFeed.latestRoundData();
require(block.timestamp - updatedAt <= MAX_PRICE_AGE, "Stale price");
require(price > 0, "Invalid price");
```

### Bug B: Missing Confidence Interval (Pyth)
```solidity
// VULNERABLE:
PythStructs.Price memory p = pyth.getPriceUnsafe(priceFeed);
return p.price;  // ignores p.conf (confidence interval)

// CORRECT:
require(p.conf * 10 <= uint64(p.price), "Price too uncertain");
// conf > 10% of price = untrustworthy
```

### Bug C: TWAP Too Short (flash loan manipulatable)
```solidity
// VULNERABLE: 60-second TWAP
uint32[] memory secondsAgos = new uint32[](2);
secondsAgos[0] = 60; secondsAgos[1] = 0;
// Flash loan can shift price for entire 60s window

// CORRECT: 1800s minimum TWAP (30 min)
```

### Bug D: Single-Source Oracle
```solidity
// VULNERABLE: only Uniswap spot price
uint price = getUniswapSpotPrice(token);  // flash loan manipulatable

// CORRECT: Chainlink primary, Uniswap TWAP as fallback, require close agreement
```

### Grep Patterns
```bash
# Missing staleness check
grep -rn "latestRoundData" contracts/ -A5 | grep -v "updatedAt\|timestamp"

# Pyth price usage — confidence interval checked?
grep -rn "getPriceUnsafe\|getPrice\b" contracts/ -A8 | grep -v "conf\|confidence"

# TWAP windows — short TWAP flag
grep -rn "secondsAgo\|TWAP\|cardinality" contracts/ -A5
```

---

## 6. ERC4626 VAULT ATTACKS

### Exchange Rate Manipulation (near-empty vault)
```solidity
// VULNERABLE — first depositor attack:
// 1. Attacker deposits 1 wei → gets 1 share
// 2. Attacker donates large amount directly (transfer, not deposit)
// 3. Exchange rate: 1 share = (1 + donation) assets
// 4. Victim deposits → rounds down to 0 shares → free donation to attacker

// CORRECT: virtual shares (OpenZeppelin v4.9+)
function _decimalsOffset() internal view virtual override returns (uint8) {
    return 9;  // add 1e9 virtual shares + assets to prevent manipulation
}
```

### ERC4626 Transfer (moves shares but not stake/lock records)
```solidity
// VULNERABLE: shares transferred, but lock records stay with original owner
// → shares stuck, can't redeem → permanent freeze (Belong pattern)
function transfer(address to, uint256 amount) external override {
    _transfer(msg.sender, to, amount);  // moves shares
    // MISSING: transfer lock record from msg.sender to `to`
}
```

### Grep Patterns
```bash
grep -rn "function transfer\|function transferFrom" contracts/ -A15
grep -rn "function deposit\|function mint\|function withdraw\|function redeem" contracts/ -A10
```

---
