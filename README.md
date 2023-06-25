# Smart Contract Auditing for Dummies

The below document contains a list of vulnerabilities and simple mistakes that a security researcher should consider when performing a smart contract audit. I've tried my best to separate them into meaningful categories. Contributions are always welcome!

This repository is intended to be used as a guide for new and experienced auditors alike. 

## 1: Data
### 1.1: Integer Overflow / Underflow

Integer overflow occurs when the result of an arithmetic operation exceeds the maximum value that can be stored in the integer's bit representation. Integer underflow occurs when an unsigned integer is set to a negative value. 

**Example**

``` solidity
pragma solidity 0.7.0;

uint8 public max = type(uint8).max;
uint8 public zero = 0;

function underflow() public {
  zero--; // result = max
}

function overflow() public {
  max++; // result = zero
}
```

**Mitigation**

Solidity version 0.8+ comes with implicit overflow and underflow checks on unsigned integers. If you are using an older compiler version, ensure you use OpenZeppelin's SafeMath library when doing arithmetic operations.

### 1.2: Rounding errors

Rounding errors occur when there is a lack of precision when performing integer division. This can lead to results being rounded towards zero.

**Example**
This is a real life example from a protocol called Yield V2. Here we can see integer division occurs before multiplication, which caused a vulnerability via imprecise accuracy when calculating the `cumulativeBalancesRatio`.

``` solidity

function _update(
        uint128 baseBalance,
        uint128 fyBalance,
        uint112 _baseCached,
        uint112 _fyTokenCached
    ) private {
        ....

            cumulativeBalancesRatio +=
                (scaledFYTokenCached / _baseCached) *
                timeElapsed;
        ....
    }
```

**Mitigation**
In order to prevent rounding errors, a developer should do the following:
- Multiplication should always occur before division to avoid a loss in precision.
- Use a flooring division instead of a rounding-towards-zero division.
- Use a higher precision in the computation of results involving integer division. Specifically, use 1e27 instead of 1e18.


### 1.3: Uninitialized variables

Ensure to check for uninitialized state variables. Whilst this on it's own isn't a vlunerability, it can lead to arithmetic errors and unexpected behavior.

### 1.4: Private Data

Just because a state variable is private, this doesn't mean it isn't readable. A smart contract stores state variables in slots, and an attacker can read the value of any storage variable by finding the corresponding slot. 

**Mitigation**

Sensitive information should not be placed in storage, and should instead not be stored in a contract when possible. When necessary, storing a sensitive variable in memory is another possible mitigation. 

### 1.5: Bad Randomness

Solidity smart contracts are deterministic. Therefore it is not possible to create a truly 'random' number within a contract. Often, you will see protocols try to mimic randomness by hashing pseudo-random numbers through the use of global variables such as `block.timestamp`, `msg.sender` and `block.coinbase`. However, if a hacker can determine these values before a transaction is sent, then they can potentially front-run or reverse engineer a generated value. For this vulnerability, context is important. If a large amount of user funds relies on verifiable randomness, then this certainly needs to be mitigated. However, the cost of implementing true randomness may not be worth it for small protocols where the effort to crack pseudo-random number generator outweighs the reward.

**Example**
``` solidity
/// This is exploitable
uint256 pseudoRandom = uint256(keccak256(abi.encodePacked(
      tx.origin,
      blockhash(block.number - 1),
      block.timestamp
    )));
```

**Mitigation**

Use oracles to generate truly random numbers that can be applied on-chain. The most common solution is Chainlink VRF, which creates a verifiably random number off-chain and propogates it on-chain.

### 1.6: Unchecked Return Value

Some tokens like USDT don't correctly implement the EIP20 standard, and their `transfer` / `transferFrom` function calls return `void` instead of a boolean. Thus, calling these functions with the correct EIP20 function signatures will always revert unless the return type is explicitly checked. 

Additionally, the `call` and `send` functions return a Boolean indicating whether the call succeeded or failed. Thus, if the call is not checked, execution will resume even if the call threw an exception. This can lead to an attacker forcing the call to fail, but still being able to update some state in a contract.

**Mitigation**

Explicitly check for the return value of calls. For the transferring of tokens, it is advised to use OpenZeppelin's SafeERC20 library.

``` solidity
/// Correctly check the return value of an external call
(bool success, bytes memory data) = _addr.call{value: msg.value, gas: 5000}();
require(success, "Call failed");

/// Safely transfer an ERC20
ERC20(this).safeTransferFrom(msg.sender, to, amount);
```


## 2: Standard

### 2.1: Implicit visibility levels

### 2.2: Stale comments

### 2.3: Non-standard naming

### 2.4: Uncapped compiler version

### 2.5: View function changes contract state

### 2.6: Improper use of require, assert and revert

### 2.7: Typos

### 2.8: Incomplete natspec

### 2.9: Correct function visibility

## 3: Dependencies

### 3.1: Unaudited dependency

### 3.2: Code is not minimized in a library

### 3.3:

## 4: Interaction

### 4.1: Reentrancy vulnerability

A reentrancy attack occurs when a contract incorrectly implements an external call to another untrusted contract. During a reentrancy attack, an attacker is able to make a recursive call back to the original function in an attempt to drain funds. This occurs when state variables used to validate a function's caller are not updated prior to an external call, and hence reentering the function will do so with the same variable values (despite the contract sending ether via an external call).

**Example**
Below is an example of a contract that is vulnerable to a reentrancy attack. This contract holds a map of account balances that allow a user to call a `withdraw` function. However, this functions calls `send` which transfers control to the calling contract without decreasing their balance until after `send` has finished executing. As a result, the attacker can repeatedly withdraw money they do not have. Credit for this explanation goes to GitHub user [crytic](https://github.com/crytic/not-so-smart-contracts/tree/master/reentrancy).
``` solidity
pragma solidity ^0.8.17;

contract DepositFunds {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);

        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");

        balances[msg.sender] = 0;
    }
}
```
The following contract shows how the vulnerable contract can be exploited. An attacker takes advantage of the non-updated state by continuously calling the `withdraw()` function in the fallback method.

``` solidity
pragma solidity ^0.8.17;

contract Attack {
    DepositFunds public depositFunds;

    constructor(address _depositFundsAddress) {
        depositFunds = DepositFunds(_depositFundsAddress);
    }

    // Fallback is called when DepositFunds sends Ether to this contract.
    fallback() external payable {
        if (address(depositFunds).balance >= 1 ether) {
            depositFunds.withdraw();
        }
    }

    function attack() external payable {
        require(msg.value >= 1 ether);
        depositFunds.deposit{value: 1 ether}();
        depositFunds.withdraw();
    }
}
```

Some example of popular reentrancy attacks are the [Dao hack](https://hackingdistributed.com/2016/06/18/analysis-of-the-dao-exploit/) and the [Spank Chain hack](https://medium.com/spankchain/we-got-spanked-what-we-know-so-far-d5ed3a0f38fe).

**Mitigations**
- Follow the **Check, Effect, Interaction** pattern. That is where the necessary checks are made (valid address etc.), the state changes are then made to the contract, and finally the external call is made. This ensures that no matter what happens within an external call, the contract state has already changed.
- Use a reentrancy function modifier. [OpenZeppelin](https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard) have a popular `ReentrancyGuard` library that when correctly applied prevents reentrancy attacks on functions with external calls.

### 4.2: Read-Only Reentrancy

A read-only reentrency is a reentrency scenario where a `view` function is reentered, which in most cases is unguarded as it does not modify the contract's state. However, if the state is inconsistent, wrong values could be reported. Other protocols relying on a return value can be tricked into reading the wrong state to perform unwanted actions.

In DeFi, many protocols integrate with one-another to read token prices or read prices of wrapped tokens minted on particular protocols. This is possible when any lending protocol supports the pool tokens from other protocols as collateral, or allows staking.

**Example**

``` solidity
contract MinimalReentrant {
  uint256 private _number;

  function vulnerableGetter() public view returns (uint256) {
    return _number;
  }

  function reentrancyExploitable() public {
    msg.sender.call("");
    _number++;
  }
}

contract MinimalVictim {
  address public reentrant;

  function doSmth() public {
    MinimalReentrant reentrant = MinimalReentrant(reentrant);
    uint256 value = reentrant.vulnerableGetter() + 1;
  }
}
```

In this *extremely* simple example, we see that the contract has all of the characteristics required for a read-only reentrancy attack. Those being:
- There is some **state** (_number)
- There is an external **call**, and the state is modified after the call
- There is another contract (**MinimalVictim**) that is dependent on this state (uitilized by getter)

As a result, an attacker can exploit this by manipulating the `vulnerableGetter()` function to return a higher `_number` value. This would in turn impact the fetched price in the `MinimalVictim` contract.

**Mitigations**
- A read-only reentrancy guard can be added to a function. This will verify whether the reentrancy guard has not been locked, and throw an error if it has.
- A function with a reentrant modifier should be called first. If this fails, the contract will be locked, and reading from it should not be possible.


### 4.3: Denial of Service - Block Gas Limit

### 4.4: Denial of Service - Unexpected Revert

External calls can fail accidentally or deliberately, which in turn can cause a DoS condition in the contract. 

### 4.4: Incorrect or lacking input validation

Check bounds and presence of arguments

## 5: Low-Level Calls

### 5.1: Self Destruct

Malicious parties can use the `selfdestruct` method of a contract to force ether to another contract. If the exploited contract uses `address(this).balance` to perform some check, this call would increase this value past the expected amount. This can cause enexpected errors in logic and allows attackers to circumvent certain checks.

**Example**
In this example, users can only deposit 0.5 eth, and the person who deposits at the target amount wins the whole pot. Here, we can use `selfdestruct` to force the Vulnerable.sol contract to receive ether, which is then checked and thus the game logic is avoided.
``` solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

contract Vulnerable {
  uint public targetBalance = 7 ether;
  address public winner;

  function deposit() public payable {
    require(msg.value == 0.5 ether, "Have to send exactly 0.5 eth");
    uint balance = address(this.balance);
    require(balance <= targetBalance, "Game is over");

    if (balance == targetBalance) {
      winner = msg.sender;
    }
  }
}


contract Attack {

  function attack(address force) public payable {
    selfdestruct(payable(force)); // send 7 ether
  }    
}  
```

**Mitigation**
Don't use `address(this).balance`. Instead, use a state variable to track the balances of users (or whatever balance is being tracked).

### 5.2: Unsafe Delegatecall

`delegatecall` preserves the context of the caller at runtime. Thus, the values of `msg.sender`, `msg.data` and `msg.value` don't change - unlike `call` where those value might change during execution. Additionally, the storage layout of both the Caller and Receiver should be the same. This can create security vulnerabilities, as an attacker can manipulate a delegation contract to unintentionally invoke a `delegatecall` using the attacker's state.

**Example**
Below is an example of how an attacker can manipulate the `Delegation` contract to call the `Delegate.pwn()` function to set themselves as the new owner. They do this by passing the function selector of `pwn()` in the calldata. Since the `Delegation` contract has no function that matches this selecter, it catches the error using the fallback function. This calls the `Delegate.pwn()` function in the context of the attacker.

``` solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Delegate {
    address public owner;

    constructor(address _owner) public {
        owner = _owner;
    }

    function pwn() public {
        owner = msg.sender;
    }
}

contract Delegation {
    address public owner;
    Delegate delegate;

    constructor(address _delegateAddress) public {
        delegate = Delegate(_delegateAddress);
        owner = msg.sender;
    }

    fallback() external {
        (bool result,) = address(delegate).delegatecall(msg.data);
        if (result) {
            this;
        }
    }
}
```

**Mitigation**
The common example of the `delegatecall` vulnerability can be prevented by using a stateless library (ie. a library contract that only exposes `pure` or `view` functions and doesn't modify state in client contracts).

### 5.3: Unchecked External Call - Call Injection

When the call data of an external function is controllable, it is easy to cause arbitrary function execution. As a result, an attacker can manipulate the behaviour of an external call when unchecked.

**Example**
The below example shows how an attacker could manipulate an unchecked external call to transfer all of the `tokenWhaleContract` tokens to them.

``` solidity
function approveAndCallcode(address _spender, uint256 _value, bytes memory _extraData)
        public
        returns (bool success)
    {
        allowance[msg.sender][_spender] = _value;

        // Call the contract code
        _spender.call(_extraData); // vulnerable point
            // return true;
    }

// Exploit call
TokenWhaleContract.approveAndCallcode(
  address(TokenWhaleContract), 0, abi.encodeWithSignature("transfer(address,uint256)", address(alice), 1000)
);
```

**Mitigation**
The use of low level `call` should be avoided where possible, especially when controllable by a user via an `external` function.