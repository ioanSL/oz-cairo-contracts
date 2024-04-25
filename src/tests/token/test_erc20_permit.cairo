use openzeppelin::token::erc20::interface::IERC20;
use openzeppelin::utils::serde::SerializedAppend;
use openzeppelin::token::erc20::erc20::ERC20Component::InternalTrait;
use openzeppelin::token::erc20::extensions::erc20_permit::{IPermit, Permit, OffchainMessageHash};
use openzeppelin::tests::mocks::erc20_permit_mocks::ERC20PermitMock;
use openzeppelin::tests::mocks::erc20_permit_mocks::ERC20PermitMock::SNIP12MetadataImpl;
use openzeppelin::tests::utils::constants::{NAME, SYMBOL, SUPPLY, ZERO, OWNER, PUBKEY, RECIPIENT};
use openzeppelin::tests::utils;
use openzeppelin::token::erc20::ERC20Component::InternalImpl as ERC20Impl;
use openzeppelin::token::erc20::extensions::ERC20PermitComponent;
use openzeppelin::utils::cryptography::snip12::STARKNET_DOMAIN_TYPE_HASH;
use openzeppelin::token::erc20::interface::{ERC20PermitABIDispatcher, ERC20PermitABIDispatcherTrait};
use openzeppelin::tests::mocks::account_mocks::DualCaseAccountMock;

use starknet::ContractAddress;
use starknet::contract_address_const;
use starknet::testing;


type ComponentState = ERC20PermitComponent::ComponentState<ERC20PermitMock::ContractState>;

fn CONTRACT_STATE() -> ERC20PermitMock::ContractState {
    ERC20PermitMock::contract_state_for_testing()
}
fn COMPONENT_STATE() -> ComponentState {
    ERC20PermitComponent::component_state_for_testing()
}

fn setup() -> (ComponentState, ERC20PermitMock::ContractState) {
    let mut state = COMPONENT_STATE();
    let mut mock_state = CONTRACT_STATE();

    mock_state.erc20._mint(OWNER(), SUPPLY);
    utils::drop_event(ZERO());
    (state, mock_state)
}

fn setup_account() -> ContractAddress {
    let mut calldata = array![0x26da8d11938b76025862be14fdb8b28438827f73e75e86f7bfa38b196951fa7];
    utils::deploy(DualCaseAccountMock::TEST_CLASS_HASH, calldata)
}

fn deploy() -> ERC20PermitABIDispatcher {
    let mut calldata = array![];
    calldata.append_serde(NAME());
    calldata.append_serde(SYMBOL());
    calldata.append_serde(SUPPLY);
    calldata.append_serde(OWNER());

    let target = utils::deploy(ERC20PermitMock::TEST_CLASS_HASH, calldata);
    ERC20PermitABIDispatcher { contract_address: target }
}


#[test]
fn test_domain_separator() {
    let (component_state, mock_state) = setup();
    let domain_separator = component_state.DOMAIN_SEPARATOR();
    mock_state.erc20permit.DOMAIN_SEPARATOR();
    assert_eq!(domain_separator, STARKNET_DOMAIN_TYPE_HASH);
}

#[test]
#[should_panic(expected: ('Permit: Expired deadline',))]
fn test_permit_expired_deadline() {
    let (mut component_state, _) = setup();
    let spender = contract_address_const::<5>();
    let amount: u256 = 10;
    let deadline: u128 = 'ts9';
    let signature = array![0, 0];

    testing::set_caller_address(OWNER());

    testing::set_block_timestamp('ts10');
    component_state.permit(
        OWNER(),
        spender,
        amount,
        deadline,
        signature,
    );
}

#[test]
#[should_panic(expected: ('Permit: Invalid signature',))]
fn test_permit_invalid_signature() {
    let (mut component_state, _) = setup();
    let owner = setup_account();
    let spender = contract_address_const::<5>();
    let amount: u256 = 10;
    let deadline: u128 = 'ts10';
    let signature = array![0, 0];

    testing::set_caller_address(owner);
    component_state.permit(
        owner,
        spender,
        amount,
        deadline,
        signature,
    );
}

#[test]
fn test_permit() {
    testing::set_chain_id('SN_TEST');

    let owner = contract_address_const::<
        0x0460b6b4024b9dbdf26edcd2ac070b1acfb05ee3640d47da142a5ee045c2a960
    >();
    let spender = RECIPIENT();
    let amount: u256 = 10;
    let deadline: u128 = 'ts10';

    let permit = Permit {
        spender: spender,
        value: amount,
        deadline: deadline,
    };

    let hash = permit.get_message_hash(owner);
    let expected_hash = 0x4164cdafeae9c8166dad9f38b3159977a93ac79f283bd7f446e778bca45084c;
    assert_eq!(hash, expected_hash);
}