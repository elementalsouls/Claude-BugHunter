# Foundry PoC Template

> Reference content for the `web3-audit` skill. Originally FOUNDRY POC TEMPLATE of the monolithic SKILL.md (refactored 2026-11-18 for size/load efficiency).

## FOUNDRY POC TEMPLATE

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/VulnerableContract.sol";

contract ExploitTest is Test {
    VulnerableContract target;
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {
        // Fork mainnet at specific block
        vm.createSelectFork("mainnet", BLOCK_NUMBER);

        // Deploy or load target
        target = VulnerableContract(TARGET_ADDRESS);

        // Fund accounts
        deal(address(token), attacker, INITIAL_BALANCE);
        deal(address(token), victim, VICTIM_BALANCE);
    }

    function test_exploit() public {
        console.log("Attacker balance before:", token.balanceOf(attacker));

        vm.startPrank(attacker);

        // Step 1: Setup conditions
        // Step 2: Execute exploit
        // Step 3: Verify impact

        vm.stopPrank();

        console.log("Attacker balance after:", token.balanceOf(attacker));
        assertGt(token.balanceOf(attacker), INITIAL_BALANCE, "Exploit failed");
    }
}
```

### Key Foundry Cheatcodes
```solidity
vm.prank(address)           // next call from address
vm.startPrank(address)      // all calls from address until stopPrank()
vm.deal(address, amount)    // set ETH balance
deal(token, address, amount) // set ERC20 balance
vm.warp(timestamp)          // set block.timestamp
vm.roll(blockNumber)        // set block.number
vm.createSelectFork("mainnet", blockNumber)  // fork mainnet
vm.expectRevert(bytes)      // next call should revert
vm.label(address, "name")   // label for trace output
vm.assume(condition)        // fuzz: discard inputs where false
```

### Running Tests
```bash
# Run specific test
forge test --match-test test_exploit -vvvv

# Run with fork
forge test --match-test test_exploit -vvvv --fork-url $MAINNET_RPC

# Gas report
forge test --gas-report

# Coverage
forge coverage --report summary
```

---
