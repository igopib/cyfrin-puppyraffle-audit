### [H-1] Function enterRaffle does not make user pay for raffle tickets.

**Description:** The point of `PuppyRaffle::enterRaffle` is to have users pay for tickets in the transaction. But there is no call made to send value from user to the smart contract.

Below is one such example to read data off chain.

**Impact:** Function checks if ETH is being sent is greater than equal ticket price but does not actually send the transaction value, or confirms if it is being sent.

**Proof of Concept:**

**Recommended Mitigation:**
Severity: HIGH

### [M-#] Function `PuppyRaffle::enterRaffle` is exposed to DOS(Denial of service attacks, looping through unchecked players array.

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
Severity: HIGH

```

```
