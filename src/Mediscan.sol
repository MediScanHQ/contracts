// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/interfaces/IERC20.sol";

contract Mediscan is AccessControl {
    uint256 constant MAX_INT = 2**256 - 1;

    bytes32 constant USER_ADMIN_ROLE = keccak256(abi.encodePacked("USER_ADMIN_ROLE"));
    bytes32 constant PAYMENT_ADMIN_ROLE = keccak256(abi.encodePacked("PAYMENT_ADMIN_ROLE"));
    bytes32 constant HEALTH_PROFESSIONAL_FULL = keccak256(abi.encodePacked("HEALTH_PROFESSIONAL_FULL"));
    bytes32 constant HEALTH_PROFESSIONAL_MID = keccak256(abi.encodePacked("HEALTH_PROFESSIONAL_MID"));
    bytes32 constant HEALTH_PROFESSIONAL_LOW = keccak256(abi.encodePacked("HEALTH_PROFESSIONAL_LOW"));

    mapping(bytes32 => bool) public registeredFaceHashes;

    mapping(bytes32 => mapping(address => uint256)) public balanceForTokenForFaceHash;
    mapping(bytes32 => uint256) public baseTokenBalanceForFaceHash;

    event SendTokenToFaceHash(bytes32 indexed _faceHash, address indexed _token, uint256 indexed _amount);
    event SendChainBaseTokenToFaceHash(bytes32 indexed _faceHash, uint256 indexed _amount);
    event PayoutTokenForFaceHash(bytes32 indexed _faceHash, address indexed _token, uint256 indexed _amount);
    event PayoutChainBaseTokenToFaceHash(bytes32 indexed _faceHash, address indexed _account);
    event VerifyHealthWorker(address indexed _account, uint256 indexed _accessLevel);
    event RegisterFaceHash(bytes32 indexed _faceHash);

    modifier onlyAdmin() {
        _checkRole(DEFAULT_ADMIN_ROLE);
        _;
    }

    modifier onlyUserAdmin() {
        _checkRole(USER_ADMIN_ROLE);
        _;
    }

    modifier onlyPaymentAdmin() {
        _checkRole(PAYMENT_ADMIN_ROLE);
        _;
    }

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setRoleAdmin(USER_ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(HEALTH_PROFESSIONAL_FULL, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(HEALTH_PROFESSIONAL_MID, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(HEALTH_PROFESSIONAL_LOW, DEFAULT_ADMIN_ROLE);
    }

    function getAccessLevelForAddress(address _address) external view returns (uint256) {
        if (hasRole(HEALTH_PROFESSIONAL_FULL, _address)) {
            return 0;
        } else if (hasRole(HEALTH_PROFESSIONAL_MID, _address)) {
            return 1;
        } else if (hasRole(HEALTH_PROFESSIONAL_LOW, _address)) {
            return 2;
        } else {
            return MAX_INT;
        }
    }

    function isFaceHashRegistered(bytes32 _hash) external view returns (bool) {
        return registeredFaceHashes[_hash];
    }

    function sendTokenToFaceHash(bytes32 _faceHash, address _token, uint256 _amount) external {
        IERC20(_token).transferFrom(msg.sender, address(this), _amount);
        balanceForTokenForFaceHash[_faceHash][_token] += _amount;
        emit SendTokenToFaceHash(_faceHash, _token, _amount);
    }

    function sendChainBaseTokenToFaceHash(bytes32 _faceHash) external payable {
        baseTokenBalanceForFaceHash[_faceHash] += msg.value;
        emit SendChainBaseTokenToFaceHash(_faceHash, msg.value);
    }

    function payoutTokenForFaceHash(bytes32 _faceHash, address _token,  address _account) external onlyPaymentAdmin {
        uint256 amount = balanceForTokenForFaceHash[_faceHash][_token];
        IERC20(_token).transfer(_account, amount);
        balanceForTokenForFaceHash[_faceHash][_token] -= amount;
        emit PayoutTokenForFaceHash(_faceHash, _token, amount);
    }

    function payoutChainBaseTokenToFaceHash(bytes32 _faceHash, address _account) external onlyPaymentAdmin {
        uint256 amount = baseTokenBalanceForFaceHash[_faceHash];
        (bool success, ) = _account.call{value: amount}("");
        require(success, "Payout failed");
        baseTokenBalanceForFaceHash[_faceHash] -= amount;
        emit PayoutChainBaseTokenToFaceHash(_faceHash, _account);
    }

    function addUserAdmin(address _account) external onlyAdmin {
        _grantRole(USER_ADMIN_ROLE, _account);
    }

    function removeUserAdmin(address _account) external onlyAdmin {
        _revokeRole(USER_ADMIN_ROLE, _account);
    }

    function addPaymentAdmin(address _account) external onlyAdmin {
        _grantRole(PAYMENT_ADMIN_ROLE, _account);
    }

    function removePaymentAdmin(address _account) external onlyAdmin {
        _revokeRole(PAYMENT_ADMIN_ROLE, _account);
    }

    function verifyHealthWorker(address _account, uint256 _accessLevel) external onlyAdmin {
        if (_accessLevel == 0) {
            _grantRole(HEALTH_PROFESSIONAL_FULL, _account);
        } else if (_accessLevel == 1) {
            _grantRole(HEALTH_PROFESSIONAL_MID, _account);
        } else if (_accessLevel == 2) {
            _grantRole(HEALTH_PROFESSIONAL_LOW, _account);
        } else {
            revert("Unrecognized access level");
        }
        emit VerifyHealthWorker(_account, _accessLevel);
    }

    function registerFaceHash(bytes32 _faceHash) external onlyUserAdmin {
        registeredFaceHashes[_faceHash] = true;
        emit RegisterFaceHash(_faceHash);
    }
}