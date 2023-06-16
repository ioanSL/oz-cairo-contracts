use traits::Into;
use array::ArrayTrait;
use starknet::ContractAddress;
use starknet::contract_address_const;
use starknet::testing::set_caller_address;
use starknet::testing::set_contract_address;
use openzeppelin::token::erc721::ERC721;
use openzeppelin::token::erc721::interface::IERC721;
use openzeppelin::token::erc721::interface::IERC721Camel;
use openzeppelin::token::erc721::interface::IERC721Dispatcher;
use openzeppelin::token::erc721::interface::IERC721CamelDispatcher;
use openzeppelin::token::erc721::interface::IERC721DispatcherTrait;
use openzeppelin::token::erc721::interface::IERC721CamelDispatcherTrait;
use openzeppelin::token::erc721::dual721::DualCaseERC721Trait;
use openzeppelin::token::erc721::dual721::DualCaseERC721;
use openzeppelin::tests::mocks::snake721_mock::SnakeERC721Mock;
use openzeppelin::tests::mocks::camel721_mock::CamelERC721Mock;
use openzeppelin::tests::mocks::erc721_receiver::ERC721Receiver;
use openzeppelin::tests::mocks::erc721_receiver::SUCCESS;
use openzeppelin::tests::mocks::erc721_receiver::FAILURE;
use openzeppelin::tests::mocks::erc721_panic::SnakeERC721Panic;
use openzeppelin::tests::mocks::erc721_panic::CamelERC721Panic;
use openzeppelin::tests::mocks::non721_mock::NonERC721;
use openzeppelin::tests::utils;

use openzeppelin::tests::utils::PanicTrait;

///
/// constants
///

const NAME: felt252 = 111;
const SYMBOL: felt252 = 222;
const URI: felt252 = 333;

fn TOKEN_ID() -> u256 {
    7.into()
}
fn OWNER() -> ContractAddress {
    contract_address_const::<10>()
}
fn RECIPIENT() -> ContractAddress {
    contract_address_const::<20>()
}
fn SPENDER() -> ContractAddress {
    contract_address_const::<30>()
}
fn OPERATOR() -> ContractAddress {
    contract_address_const::<40>()
}
fn DATA(success: bool) -> Span<felt252> {
    let mut data = ArrayTrait::new();
    if success {
        data.append(SUCCESS);
    } else {
        data.append(FAILURE);
    }
    data.span()
}

///
/// setup
///

fn setup_snake() -> (DualCaseERC721, IERC721Dispatcher) {
    let mut calldata = ArrayTrait::new();
    calldata.append(NAME);
    calldata.append(SYMBOL);
    calldata.append(TOKEN_ID().low.into());
    calldata.append(TOKEN_ID().high.into());
    set_caller_address(OWNER());
    let target = utils::deploy(SnakeERC721Mock::TEST_CLASS_HASH, calldata);
    (DualCaseERC721 { contract_address: target }, IERC721Dispatcher { contract_address: target })
}

fn setup_camel() -> (DualCaseERC721, IERC721CamelDispatcher) {
    let mut calldata = ArrayTrait::new();
    calldata.append(NAME);
    calldata.append(SYMBOL);
    calldata.append(TOKEN_ID().low.into());
    calldata.append(TOKEN_ID().high.into());
    set_caller_address(OWNER());
    let target = utils::deploy(CamelERC721Mock::TEST_CLASS_HASH, calldata);
    (
        DualCaseERC721 {
            contract_address: target
            }, IERC721CamelDispatcher {
            contract_address: target
        }
    )
}

fn setup_non_erc721() -> DualCaseERC721 {
    let calldata = ArrayTrait::new();
    let target = utils::deploy(NonERC721::TEST_CLASS_HASH, calldata);
    DualCaseERC721 { contract_address: target }
}

fn setup_erc721_panic() -> (DualCaseERC721, DualCaseERC721) {
    let snake_target = utils::deploy(SnakeERC721Panic::TEST_CLASS_HASH, ArrayTrait::new());
    let camel_target = utils::deploy(CamelERC721Panic::TEST_CLASS_HASH, ArrayTrait::new());
    (
        DualCaseERC721 {
            contract_address: snake_target
            }, DualCaseERC721 {
            contract_address: camel_target
        }
    )
}

fn setup_receiver() -> ContractAddress {
    utils::deploy(ERC721Receiver::TEST_CLASS_HASH, ArrayTrait::new())
}

///
/// case agnostic methods
///

#[test]
#[available_gas(2000000)]
fn test_dual_name() {
    let (snake_dispatcher, _) = setup_snake();
    let (camel_dispatcher, _) = setup_camel();
    assert(snake_dispatcher.name() == NAME, 'Should return name');
    assert(camel_dispatcher.name() == NAME, 'Should return name');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('ENTRYPOINT_NOT_FOUND', ))]
fn test_dual_no_name() {
    let dispatcher = setup_non_erc721();
    dispatcher.name();
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_name_exists_and_panics() {
    let (dispatcher, _) = setup_erc721_panic();
    dispatcher.name();
}

#[test]
#[available_gas(2000000)]
fn test_dual_symbol() {
    let (snake_dispatcher, _) = setup_snake();
    let (camel_dispatcher, _) = setup_camel();
    assert(snake_dispatcher.symbol() == SYMBOL, 'Should return symbol');
    assert(camel_dispatcher.symbol() == SYMBOL, 'Should return symbol');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('ENTRYPOINT_NOT_FOUND', ))]
fn test_dual_no_symbol() {
    let dispatcher = setup_non_erc721();
    dispatcher.symbol();
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_symbol_exists_and_panics() {
    let (dispatcher, _) = setup_erc721_panic();
    dispatcher.symbol();
}

#[test]
#[available_gas(2000000)]
fn test_dual_approved() {
    let (snake_dispatcher, snake_target) = setup_snake();
    set_contract_address(OWNER());
    snake_target.approve(SPENDER(), TOKEN_ID());
    assert(snake_target.get_approved(TOKEN_ID()) == SPENDER(), 'Spender not approved correctly');

    let (camel_dispatcher, camel_target) = setup_camel();
    set_contract_address(OWNER());
    camel_dispatcher.approve(SPENDER(), TOKEN_ID());
    assert(camel_target.getApproved(TOKEN_ID()) == SPENDER(), 'Spender not approved correctly');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('ENTRYPOINT_NOT_FOUND', ))]
fn test_dual_no_approve() {
    let dispatcher = setup_non_erc721();
    dispatcher.approve(SPENDER(), TOKEN_ID());
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_approve_exists_and_panics() {
    let (dispatcher, _) = setup_erc721_panic();
    dispatcher.approve(SPENDER(), TOKEN_ID());
}

///
/// snake_case target
///

#[test]
#[available_gas(2000000)]
fn test_dual_balance_of() {
    let (dispatcher, _) = setup_snake();
    assert(dispatcher.balance_of(OWNER()) == 1, 'Should return balance');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('ENTRYPOINT_NOT_FOUND', ))]
fn test_dual_no_balance_of() {
    let dispatcher = setup_non_erc721();
    dispatcher.balance_of(OWNER());
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_balance_of_exists_and_panics() {
    let (dispatcher, _) = setup_erc721_panic();
    dispatcher.balance_of(OWNER());
}

#[test]
#[available_gas(2000000)]
fn test_dual_owner_of() {
    let (dispatcher, target) = setup_snake();
    assert(dispatcher.owner_of(TOKEN_ID()) == OWNER(), 'Should return owner');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('ENTRYPOINT_NOT_FOUND', ))]
fn test_dual_no_owner_of() {
    let dispatcher = setup_non_erc721();
    dispatcher.owner_of(TOKEN_ID());
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_owner_of_exists_and_panics() {
    let (dispatcher, _) = setup_erc721_panic();
    dispatcher.owner_of(TOKEN_ID());
}

#[test]
#[available_gas(2000000)]
fn test_dual_transfer_from() {
    let (dispatcher, target) = setup_snake();
    dispatcher.transfer_from(OWNER(), RECIPIENT(), TOKEN_ID());
    assert(target.owner_of(TOKEN_ID()) == RECIPIENT(), 'Should transfer token');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('ENTRYPOINT_NOT_FOUND', ))]
fn test_dual_no_transfer_from() {
    let dispatcher = setup_non_erc721();
    dispatcher.transfer_from(OWNER(), RECIPIENT(), TOKEN_ID());
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_transfer_from_exists_and_panics() {
    let (dispatcher, _) = setup_erc721_panic();
    dispatcher.transfer_from(OWNER(), RECIPIENT(), TOKEN_ID());
}

#[test]
#[available_gas(2000000)]
fn test_dual_safe_transfer_from() {
    let (dispatcher, target) = setup_snake();
    let receiver = setup_receiver();
    set_contract_address(OWNER());
    dispatcher.safe_transfer_from(OWNER(), receiver, TOKEN_ID(), DATA(true));
    assert(target.owner_of(TOKEN_ID()) == receiver, 'Should transfer token');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('ENTRYPOINT_NOT_FOUND', ))]
fn test_dual_no_safe_transfer_from() {
    let dispatcher = setup_non_erc721();
    dispatcher.safe_transfer_from(OWNER(), RECIPIENT(), TOKEN_ID(), DATA(true));
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_safe_transfer_from_exists_and_panics() {
    let (dispatcher, _) = setup_erc721_panic();
    dispatcher.safe_transfer_from(OWNER(), RECIPIENT(), TOKEN_ID(), DATA(true));
}

#[test]
#[available_gas(2000000)]
fn test_dual_get_approved() {
    let (dispatcher, target) = setup_snake();
    set_contract_address(OWNER());
    target.approve(SPENDER(), TOKEN_ID());
    assert(dispatcher.get_approved(TOKEN_ID()) == SPENDER(), 'Should return approval');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('ENTRYPOINT_NOT_FOUND', ))]
fn test_dual_no_get_approved() {
    let dispatcher = setup_non_erc721();
    dispatcher.get_approved(TOKEN_ID());
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_get_approved_exists_and_panics() {
    let (dispatcher, _) = setup_erc721_panic();
    dispatcher.get_approved(TOKEN_ID());
}

#[test]
#[available_gas(2000000)]
fn test_dual_set_approval_for_all() {
    let (dispatcher, target) = setup_snake();
    set_contract_address(OWNER());
    dispatcher.set_approval_for_all(OPERATOR(), true);
    assert(target.is_approved_for_all(OWNER(), OPERATOR()), 'Operator not approved correctly');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('ENTRYPOINT_NOT_FOUND', ))]
fn test_dual_no_set_approval_for_all() {
    let dispatcher = setup_non_erc721();
    dispatcher.set_approval_for_all(OPERATOR(), true);
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_set_approval_for_all_exists_and_panics() {
    let (dispatcher, _) = setup_erc721_panic();
    dispatcher.set_approval_for_all(OPERATOR(), true);
}

#[test]
#[available_gas(2000000)]
fn test_dual_is_approved_for_all() {
    let (dispatcher, target) = setup_snake();
    set_contract_address(OWNER());
    target.set_approval_for_all(OPERATOR(), true);
    assert(dispatcher.is_approved_for_all(OWNER(), OPERATOR()), 'Operator not approved correctly');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('ENTRYPOINT_NOT_FOUND', ))]
fn test_dual_no_is_approved_for_all() {
    let dispatcher = setup_non_erc721();
    dispatcher.is_approved_for_all(OWNER(), OPERATOR());
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_is_approved_for_all_exists_and_panics() {
    let (dispatcher, _) = setup_erc721_panic();
    dispatcher.is_approved_for_all(OWNER(), OPERATOR());
}

#[test]
#[available_gas(2000000)]
fn test_dual_token_uri() {// to do: implement
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('ENTRYPOINT_NOT_FOUND', ))]
fn test_dual_no_token_uri() {
    let dispatcher = setup_non_erc721();
    dispatcher.token_uri(TOKEN_ID());
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_token_uri_exists_and_panics() {
    let (dispatcher, _) = setup_erc721_panic();
    dispatcher.token_uri(TOKEN_ID());
}

///
/// camelCase target
///

#[test]
#[available_gas(2000000)]
fn test_dual_balanceOf() {
    let (dispatcher, _) = setup_camel();
    assert(dispatcher.balance_of(OWNER()) == 1, 'Should return balance');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_balanceOf_exists_and_panics() {
    let (_, dispatcher) = setup_erc721_panic();
    dispatcher.balance_of(OWNER());
}

#[test]
#[available_gas(2000000)]
fn test_dual_ownerOf() {
    let (dispatcher, target) = setup_camel();
    assert(dispatcher.owner_of(TOKEN_ID()) == OWNER(), 'Should return owner');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_ownerOf_exists_and_panics() {
    let (_, dispatcher) = setup_erc721_panic();
    dispatcher.owner_of(TOKEN_ID());
}

#[test]
#[available_gas(2000000)]
fn test_dual_transferFrom() {
    let (dispatcher, target) = setup_camel();
    set_contract_address(OWNER());
    dispatcher.transfer_from(OWNER(), RECIPIENT(), TOKEN_ID());
    assert(target.ownerOf(TOKEN_ID()) == RECIPIENT(), 'Should transfer token');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_transferFrom_exists_and_panics() {
    let (_, dispatcher) = setup_erc721_panic();
    dispatcher.transfer_from(OWNER(), RECIPIENT(), TOKEN_ID());
}

#[test]
#[available_gas(2000000)]
fn test_dual_safeTransferFrom() {
    let (dispatcher, target) = setup_camel();
    let receiver = setup_receiver();
    set_contract_address(OWNER());
    dispatcher.safe_transfer_from(OWNER(), receiver, TOKEN_ID(), DATA(true));
    assert(target.ownerOf(TOKEN_ID()) == receiver, 'Should transfer token');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_safeTransferFrom_exists_and_panics() {
    let (_, dispatcher) = setup_erc721_panic();
    dispatcher.safe_transfer_from(OWNER(), RECIPIENT(), TOKEN_ID(), DATA(true));
}

#[test]
#[available_gas(2000000)]
fn test_dual_getApproved() {
    let (dispatcher, target) = setup_camel();
    set_contract_address(OWNER());
    target.approve(SPENDER(), TOKEN_ID());
    assert(dispatcher.get_approved(TOKEN_ID()) == SPENDER(), 'Should return approval');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_getApproved_exists_and_panics() {
    let (_, dispatcher) = setup_erc721_panic();
    dispatcher.get_approved(TOKEN_ID());
}

#[test]
#[available_gas(2000000)]
fn test_dual_setApprovalForAll() {
    let (dispatcher, target) = setup_camel();
    set_contract_address(OWNER());
    dispatcher.set_approval_for_all(OPERATOR(), true);
    assert(target.isApprovedForAll(OWNER(), OPERATOR()), 'Operator not approved correctly');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_setApprovalForAll_exists_and_panics() {
    let (_, dispatcher) = setup_erc721_panic();
    set_contract_address(OWNER());
    dispatcher.set_approval_for_all(OPERATOR(), true);
}

#[test]
#[available_gas(2000000)]
fn test_dual_isApprovedForAll() {
    let (dispatcher, target) = setup_camel();
    set_contract_address(OWNER());
    target.setApprovalForAll(OPERATOR(), true);
    assert(dispatcher.is_approved_for_all(OWNER(), OPERATOR()), 'Operator not approved correctly');
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_isApprovedForAll_exists_and_panics() {
    let (_, dispatcher) = setup_erc721_panic();
    dispatcher.is_approved_for_all(OWNER(), OPERATOR());
}

#[test]
#[available_gas(2000000)]
fn test_dual_tokenUri() {//to do: implement
}

#[test]
#[available_gas(2000000)]
#[should_panic(expected: ('Some error', 'ENTRYPOINT_FAILED', ))]
fn test_dual_tokenUri_exists_and_panics() {
    let (_, dispatcher) = setup_erc721_panic();
    dispatcher.token_uri(TOKEN_ID());
}
