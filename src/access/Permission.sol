// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title Permission
 * @dev Binary Roles Recommended Slots
 * 0x01  |  0x10
 * 0x02  |  0x20
 * 0x04  |  0x40
 * 0x08  |  0x80
 *
 * Don't use other slots unless you are familiar with bitewise operations
 */
abstract contract Permission {
  error InvalidPermission(bytes1 permissionNeeded);
  error PermissionAdminCannotBeEmpty();

  event SetPermissionAdmin(address admin);
  event PermissionChanged(address indexed target, bytes1 permission);

  mapping(address => bytes1) internal permissions;
  address private admin;

  modifier onlyPermission(bytes1 access) {
    if (permissions[msg.sender] & access == 0) revert InvalidPermission(access);
    _;
  }

  modifier onlyPermissionAdmin() {
    if (msg.sender != admin) revert InvalidPermission(0x00);
    _;
  }

  constructor(address _permissionAdmin) {
    if (_permissionAdmin == address(0)) revert PermissionAdminCannotBeEmpty();

    admin = _permissionAdmin;
    emit SetPermissionAdmin(_permissionAdmin);
  }

  function renouncePermissionAdmin() external onlyPermissionAdmin {
    admin = address(0);
    emit SetPermissionAdmin(address(0));
  }

  function transferPermissionAdmin(address _newAdmin) external onlyPermissionAdmin {
    admin = _newAdmin;
    emit SetPermissionAdmin(_newAdmin);
  }

  function setPermission(address _address, bytes1 _permission)
    external
    onlyPermissionAdmin
  {
    _setPermission(_address, _permission);
  }

  function _setPermission(address _address, bytes1 _permission) internal virtual {
    permissions[_address] = _permission;
    emit PermissionChanged(_address, _permission);
  }

  function addPermission(address _address, bytes1 _permission)
    external
    onlyPermissionAdmin
  {
    _addPermission(_address, _permission);
  }

  function _addPermission(address _address, bytes1 _permission) internal virtual {
    permissions[_address] |= _permission;
    emit PermissionChanged(_address, permissions[_address]);
  }

  function removePermission(address _address, bytes1 _permission)
    external
    onlyPermissionAdmin
  {
    _removePermission(_address, _permission);
  }

  function _removePermission(address _address, bytes1 _permission) internal virtual {
    permissions[_address] &= ~_permission;
    emit PermissionChanged(_address, permissions[_address]);
  }

  function clearPermission(address _address) external onlyPermissionAdmin {
    _clearPermission(_address);
  }

  function _clearPermission(address _address) internal virtual {
    _setPermission(_address, 0x00);
  }

  function getPermission(address _address) external view returns (bytes1) {
    return permissions[_address];
  }

  function hasPermission(address _address, bytes1 accessLevel) public view returns (bool) {
    return permissions[_address] & accessLevel != 0;
  }

  function permissionAdmin() public view returns (address) {
    return admin;
  }
}
