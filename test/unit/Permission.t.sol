// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.7;

import "../base/BaseTest.t.sol";
import { Permission } from "../../src/access/Permission.sol";

contract PermissionTest is BaseTest {
  address private owner;
  address[] private usersWithAccess;

  HarnessPermission private underTest;

  function setUp() public {
    owner = generateAddress("Owner");

    underTest = new HarnessPermission(owner);
    vm.startPrank(owner);

    uint256 size = underTest.getTotalAccess();

    for (uint256 i = 0; i < size; ++i) {
      address user = generateAddress("User With Access");
      usersWithAccess.push(user);
      underTest.setPermission(user, bytes1(underTest.ACCESS_LIST(i)));
    }
    vm.stopPrank();
  }

  function test_constructor_givenZeroAddress_thenReverts() public {
    underTest = new HarnessPermission(owner);
    vm.expectRevert(Permission.PermissionAdminCannotBeEmpty.selector);
    new HarnessPermission(ZERO_ADDRESS);
  }

  function test_constructor_thenSetsPermissionAdmin() public {
    expectExactEmit();
    emit Permission.SetPermissionAdmin(owner);
    underTest = new HarnessPermission(owner);

    assertEq(underTest.permissionAdmin(), owner);
  }

  function test_setPermission_asUser_thenReverts() public prankAs(usersWithAccess[0]) {
    vm.expectRevert(abi.encodeWithSelector(Permission.InvalidPermission.selector, 0x00));
    underTest.setPermission(owner, 0x01);
  }

  function test_setPermission_asOwner_thenGivePermission() public prankAs(owner) {
    address target = address(0x123);
    bytes1 expectedPermission = 0x08;

    underTest.setPermission(target, expectedPermission);

    assertEq(underTest.getPermission(target), expectedPermission);
  }

  function test_addPermission_asUser_thenReverts() public prankAs(usersWithAccess[0]) {
    vm.expectRevert(abi.encodeWithSelector(Permission.InvalidPermission.selector, 0x00));
    underTest.addPermission(owner, 0x01);
  }

  function test_addPermission_asOwner_thenAddsPermission() public prankAs(owner) {
    address target = address(0x123);
    bytes1 addOne = 0x01;
    bytes1 addTwo = 0x02;

    underTest.addPermission(target, addOne);
    underTest.addPermission(target, addTwo);

    assertTrue(underTest.hasPermission(target, addOne));
    assertTrue(underTest.hasPermission(target, addTwo));
  }

  function test_removePermission_asUser_thenReverts() public prankAs(usersWithAccess[0]) {
    vm.expectRevert(abi.encodeWithSelector(Permission.InvalidPermission.selector, 0x00));
    underTest.removePermission(owner, 0x01);
  }

  function test_removePermission_asOwner_thenRemovesPermission() public prankAs(owner) {
    address target = address(0x123);

    underTest.setPermission(target, bytes1(0x01) | bytes1(0x02) | bytes1(0x04));
    underTest.removePermission(target, bytes1(0x02));

    assertTrue(underTest.hasPermission(target, 0x01));
    assertTrue(underTest.hasPermission(target, 0x04));
    assertFalse(underTest.hasPermission(target, 0x02));
  }

  function test_hasPermission_asEachAccessType_thenRevertsOnEveryCallButOne() public {
    uint256 arrayLength = usersWithAccess.length;

    for (uint256 i = 0; i < arrayLength; ++i) {
      vm.startPrank(usersWithAccess[i]);
      {
        for (uint256 y = 0; y < arrayLength; ++y) {
          if (y != i) {
            bytes1 expectedPermission = bytes1(underTest.ACCESS_LIST(y));
            vm.expectRevert(
              abi.encodeWithSelector(
                Permission.InvalidPermission.selector, expectedPermission
              )
            );
          }

          underTest.dynamicSingleAccessTest(y);
        }
      }
      vm.stopPrank();
    }
  }

  function test_transferPermissionAdmin_asOwner_thenTransfersDefaultAdmin()
    public
    prankAs(owner)
  {
    address newOwner = generateAddress("New Owner");

    expectExactEmit();
    emit Permission.SetPermissionAdmin(newOwner);
    underTest.transferPermissionAdmin(newOwner);

    assertEq(underTest.permissionAdmin(), newOwner);
  }

  function test_renouncePermissionAdmin_asOwner_thenRemoveOwnership()
    public
    prankAs(owner)
  {
    expectExactEmit();
    emit Permission.SetPermissionAdmin(address(0));
    underTest.renouncePermissionAdmin();

    assertEq(underTest.permissionAdmin(), address(0));
  }

  function test_clearPermission_givenUserWithAccess_thenReturnsZeroAccess()
    public
    prankAs(owner)
  {
    address target = usersWithAccess[0];
    underTest.setPermission(target, 0x01);
    underTest.clearPermission(target);
    assertEq(underTest.getPermission(target), 0x00);
  }
}

contract HarnessPermission is Permission {
  uint8[] public ACCESS_LIST = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];

  bytes1 public ACCESS_01 = 0x01;
  bytes1 public ACCESS_02 = 0x02;
  bytes1 public ACCESS_04 = 0x04;
  bytes1 public ACCESS_08 = 0x08;

  bytes1 public ACCESS_10 = 0x10;
  bytes1 public ACCESS_20 = 0x20;
  bytes1 public ACCESS_40 = 0x40;
  bytes1 public ACCESS_80 = 0x80;

  function getTotalAccess() external view returns (uint256) {
    return ACCESS_LIST.length;
  }

  constructor(address _defaultAdmin) Permission(_defaultAdmin) { }

  function dynamicSingleAccessTest(uint256 accessId)
    external
    onlyPermission(bytes1(ACCESS_LIST[accessId]))
  { }
}
