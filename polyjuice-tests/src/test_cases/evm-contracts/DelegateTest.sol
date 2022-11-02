pragma solidity >=0.4.0 <0.7.0;

contract DelegateCallTest {
  uint storedData;

  constructor() public payable {
    storedData = 123;
  }

  function set(address ss) public payable {
    
    ss.delegatecall(abi.encodeWithSignature("set(uint256)"));
  }

}
