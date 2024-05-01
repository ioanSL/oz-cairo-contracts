// use openzeppelin::token::erc20::interface::IERC20;
// use openzeppelin::utils::serde::SerializedAppend;
// use openzeppelin::token::erc20::erc20::ERC20Component::InternalTrait;

// use openzeppelin::tests::utils;
// use openzeppelin::token::erc20::ERC20Component::InternalImpl as ERC20Impl;
// use openzeppelin::token::erc20::extensions::ERC20PermitComponent;
// use openzeppelin::utils::cryptography::snip12::STARKNET_DOMAIN_TYPE_HASH;
// use openzeppelin::tests::mocks::account_mocks::DualCaseAccountMock;

// use starknet::ContractAddress;
// use starknet::contract_address_const;


#[cfg(test)]
mod testERC20Permit{
    use core::array::ArrayTrait;
use snforge_std::cheatcodes::events::EventFetcher;
use snforge_std::signature::VerifierTrait;
use snforge_std::signature::SignerTrait;
use openzeppelin::utils::cryptography::snip12::StructHash;
use core::traits::Into;
    use core::traits::TryInto;
    use core::result::ResultTrait;
    use starknet::ContractAddress;

    use openzeppelin::tests::utils::constants::{NAME, SYMBOL, SUPPLY, ZERO, OWNER, PUBKEY, RECIPIENT};
    use openzeppelin::tests::mocks::erc20_permit_mocks::ERC20PermitMock;
    use openzeppelin::token::erc20::interface::{ERC20PermitABIDispatcher, ERC20PermitABIDispatcherTrait};
    use openzeppelin::tests::mocks::erc20_permit_mocks::ERC20PermitMock::SNIP12MetadataImpl;
    use openzeppelin::token::erc20::extensions::erc20_permit::{IPermit, Permit, OffchainMessageHash};
    use openzeppelin::presets::interfaces::account::AccountUpgradeableABIDispatcher;

    use snforge_std::{declare, ContractClassTrait, start_warp, CheatTarget, ContractClass, spy_events, SpyOn, event_name_hash};
    use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl};
    use snforge_std::signature::{KeyPairTrait, KeyPair};


    fn deploy_erc20_permit(name: ByteArray, symbol: ByteArray, fixed_supply: u256, recipient: ContractAddress) -> ERC20PermitABIDispatcher {
        let contract_hash = declare("ERC2612").unwrap();
        let mut constructor_args: Array<felt252> = ArrayTrait::new();
        Serde::serialize(@name, ref constructor_args);
        Serde::serialize(@symbol, ref constructor_args);
        Serde::serialize(@fixed_supply, ref constructor_args);
        Serde::serialize(@recipient, ref constructor_args);

        let (contract_address, _) = contract_hash.deploy(@constructor_args).unwrap();

        return ERC20PermitABIDispatcher {contract_address: contract_address};
    }

    fn get_stark_keys() -> (felt252, felt252) {
        // StarkCurve
        let key_pair = KeyPairTrait::<felt252, felt252>::generate();
        return (key_pair.public_key, key_pair.secret_key);
    }


    fn deploy_account(contract_hash: ContractClass) -> (AccountUpgradeableABIDispatcher, KeyPair<felt252, felt252>) {
        let mut constructor_args: Array<felt252> = ArrayTrait::new();
        let key_pair = KeyPairTrait::<felt252, felt252>::generate();
        Serde::serialize(@key_pair.public_key, ref constructor_args);

        let (contract_address, _) = contract_hash.deploy(@constructor_args).unwrap();

        return (
            AccountUpgradeableABIDispatcher {contract_address: contract_address}, 
            key_pair
        );
    }

    #[test]
    fn test_deploy() {
        let contract = deploy_erc20_permit(NAME(), SYMBOL(), SUPPLY, OWNER());

        assert_eq!(contract.name(), NAME());
        assert_eq!(contract.symbol(), SYMBOL());
        assert_eq!(contract.total_supply(), SUPPLY);
        assert_eq!(contract.balance_of(OWNER()), SUPPLY);
    }

    #[test]
    #[should_panic(expected: ('Permit: Expired deadline', ))]
    fn test_permit_expired_deadline() {
        let contract = deploy_erc20_permit(NAME(), SYMBOL(), SUPPLY, OWNER());

        let deadline = 'ts9';
        let amount = 100;
        let signature: Array<felt252> = ArrayTrait::new();
        start_warp(CheatTarget::All, 'ts10');
        contract.permit(OWNER(), RECIPIENT(), amount, deadline, signature);
    }

    #[test]
    #[should_panic(expected: ('Permit: Invalid signature', ))]
    fn test_permit_invalid_signature() {
        let account_class_hash = declare("AccountUpgradeable").unwrap();
        
        let (owner, _) = deploy_account(account_class_hash);
        let contract = deploy_erc20_permit(NAME(), SYMBOL(), SUPPLY, owner.contract_address);
        let (recipient, _) = deploy_account(account_class_hash);
        let deadline = 'ts10';
        let amount = 100;

        let signature: Array<felt252> = ArrayTrait::new();
        start_warp(CheatTarget::All, 'ts9');
        contract.permit(owner.contract_address, recipient.contract_address, amount, deadline, signature);
    }

    #[test]
    fn test_permit() {
        let account_class_hash = declare("AccountUpgradeable").unwrap();
        
        let (owner, key_pair) = deploy_account(account_class_hash);
        let (recipient, _) = deploy_account(account_class_hash);
        let contract = deploy_erc20_permit(NAME(), SYMBOL(), SUPPLY, owner.contract_address);
        let deadline = 'ts10';
        let amount = 100;

        let permit = Permit {
            spender: recipient.contract_address,
            value: amount,
            deadline: deadline,
        };
        
        let msg_hash = permit.get_message_hash(owner.contract_address);
        let (r, s): (felt252, felt252) = key_pair.sign(msg_hash);

        let mut signature: Array<felt252> = ArrayTrait::new();
        Serde::serialize(@r, ref signature);
        Serde::serialize(@s, ref signature);
        contract.permit(owner.contract_address, recipient.contract_address, amount, deadline, signature);

        let mut spy = spy_events(SpyOn::One(contract.contract_address));
        spy.fetch_events();
        println!("events: {}", spy.events.is_empty());
        // let (_, event) = spy.events.is_empty();

        // assert(event.keys.at(0) == @event_name_hash('Approval'), 'Event name mismatch');

        
        assert_eq!(contract.allowance(owner.contract_address, recipient.contract_address), amount);
        assert_eq!(contract.balance_of(owner.contract_address), SUPPLY);
        println!("allowance: {}", contract.allowance(owner.contract_address, recipient.contract_address));

        contract.transfer_from(owner.contract_address, recipient.contract_address, 50);

        assert_eq!(contract.balance_of(owner.contract_address), SUPPLY - 50);
        assert_eq!(contract.balance_of(recipient.contract_address), amount);
    }
}