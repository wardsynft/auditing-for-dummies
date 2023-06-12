# Smart Contract Auditing for Dummies

The below document contains a list of vulnerabilities and simple mistakes that a security researcher should consider when performing a smart contract audit. I've tried my best to separate them into meaningful categories. Contributions are always welcome!

This repository is intended to be used as a guide for new and experienced auditors alike. 

# Table of Contents
[Integer Overflow / Underflow](#integer-overflow)

## 1: Data
### 1.1: Integer overflow / underflow

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

### 1.3 Decimal interoperability

### 1.4: Uninitialized variables

Local/state and storage

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


### 

## 3: Dependencies

### 3.1: Unaudited dependency

### 3.2: Code is not minimized in a library

### 3.3:

## 4: Interaction

### 4.1: Reentrancy vulnerability

### 4.2: Read-only reentrancy

### 4.3: Interaction occurs before state updated

### 4.4: Incorrect or lacking input validation

Check bounds and presence of arguments

### 4.5: 
