### [H-1] Function enterRaffle does not make user pay for raffle tickets.

**Description:** The point of `PuppyRaffle::enterRaffle` is to have users pay for tickets in the transaction. But there is no call made to send value from user to the smart contract.

Below is one such example to read data off chain.

**Impact:** Function checks if ETH is being sent is greater than equal ticket price but does not actually send the transaction value, or confirms if it is being sent.

**Proof of Concept:**

1. Create a locally running chain

```bash
make anvil
```

2. Deploy the contract to the chain

```
make deploy
```

3. Run the storage tool

We use `1` because that's the storage slot of `s_password` in the contract.

```
cast storage <ADDRESS_HERE> 1 --rpc-url http://127.0.0.1:8545
```

You'll get an output that looks like this:

`0x6d7950617373776f726400000000000000000000000000000000000000000014`

You can then parse that hex to a string with:

```
cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014
```

And get an output of:

```
myPassword
```

**Recommended Mitigation:**
ity: HIGH
