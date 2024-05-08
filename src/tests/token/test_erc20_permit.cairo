#[cfg(test)]
mod testERC20Permit {
    use core::array::ArrayTrait;
    use core::hash::HashStateExTrait;
    use core::result::ResultTrait;
    use core::traits::{Into, TryInto};
    use hash::{HashStateTrait, Hash};
    use openzeppelin::presets::erc2612::ERC2612::SNIP12MetadataImpl;
    use openzeppelin::presets::interfaces::account::AccountUpgradeableABIDispatcher;
    use openzeppelin::tests::utils::constants::{
        NAME, SYMBOL, SUPPLY, ZERO, OWNER, PUBKEY, RECIPIENT
    };
    use openzeppelin::token::erc20::extensions::erc20_permit::{
        IPermit, Permit, OffchainMessageHash
    };
    use openzeppelin::token::erc20::interface::{
        ERC20PermitABIDispatcher, ERC20PermitABIDispatcherTrait
    };

    use openzeppelin::utils::cryptography::snip12::{
        StructHash, StarknetDomain, STARKNET_DOMAIN_TYPE_HASH
    };
    use poseidon::PoseidonTrait;
    use snforge_std::cheatcodes::events::EventFetcher;
    use snforge_std::signature::stark_curve::{
        StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl
    };
    use snforge_std::signature::{KeyPairTrait, KeyPair};
    use snforge_std::signature::{VerifierTrait, SignerTrait};

    use snforge_std::{
        start_prank, stop_prank, declare, ContractClassTrait, start_warp, CheatTarget,
        ContractClass, spy_events, SpyOn, event_name_hash
    };

    use starknet::{ContractAddress, get_tx_info};


    fn deploy_erc20_permit(
        name: ByteArray, symbol: ByteArray, fixed_supply: u256, recipient: ContractAddress
    ) -> ERC20PermitABIDispatcher {
        let contract_hash = declare("ERC2612").unwrap();
        let mut constructor_args: Array<felt252> = ArrayTrait::new();
        Serde::serialize(@name, ref constructor_args);
        Serde::serialize(@symbol, ref constructor_args);
        Serde::serialize(@fixed_supply, ref constructor_args);
        Serde::serialize(@recipient, ref constructor_args);

        let (contract_address, _) = contract_hash.deploy(@constructor_args).unwrap();

        return ERC20PermitABIDispatcher { contract_address: contract_address };
    }

    fn get_stark_keys() -> (felt252, felt252) {
        // StarkCurve
        let key_pair = KeyPairTrait::<felt252, felt252>::generate();
        return (key_pair.public_key, key_pair.secret_key);
    }


    fn deploy_account(
        contract_hash: ContractClass
    ) -> (ContractAddress, KeyPair<felt252, felt252>) {
        let mut constructor_args: Array<felt252> = ArrayTrait::new();
        let key_pair = KeyPairTrait::<felt252, felt252>::generate();
        Serde::serialize(@key_pair.public_key, ref constructor_args);

        let (contract_address, _) = contract_hash.deploy(@constructor_args).unwrap();

        return (contract_address, key_pair);
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
    #[should_panic(expected: ('Permit: Expired deadline',))]
    fn test_permit_expired_deadline() {
        let contract = deploy_erc20_permit(NAME(), SYMBOL(), SUPPLY, OWNER());

        let deadline = 'ts9';
        let amount = 100;
        let signature: Array<felt252> = ArrayTrait::new();
        start_warp(CheatTarget::All, 'ts10');
        contract.permit(OWNER(), RECIPIENT(), amount, deadline, signature);
    }

    #[test]
    #[should_panic(expected: ('Permit: Invalid signature',))]
    fn test_permit_invalid_signature() {
        let account_class_hash = declare("AccountUpgradeable").unwrap();

        let (owner, _) = deploy_account(account_class_hash);
        let contract = deploy_erc20_permit(NAME(), SYMBOL(), SUPPLY, owner);
        let (spender, _) = deploy_account(account_class_hash);
        let deadline = 'ts10';
        let amount = 100;

        let signature: Array<felt252> = ArrayTrait::new();
        start_warp(CheatTarget::All, 'ts9');
        contract
            .permit(
                owner, spender, amount, deadline, signature
            );
    }

    #[test]
    fn test_permit() {
        let account_class_hash = declare("AccountUpgradeable").unwrap();

        let (owner, key_pair) = deploy_account(account_class_hash);
        let (spender, _) = deploy_account(account_class_hash);
        let (relayer, _) = deploy_account(account_class_hash);
        let contract = deploy_erc20_permit(NAME(), SYMBOL(), SUPPLY, owner);
        let deadline = 'ts10';
        let amount = 100;

        let permit = Permit {
            spender: spender, value: amount, deadline: deadline,
        };

        let msg_hash = permit.get_message_hash(owner);
        let (r, s): (felt252, felt252) = key_pair.sign(msg_hash);

        let mut signature: Array<felt252> = ArrayTrait::new();
        Serde::serialize(@r, ref signature);
        Serde::serialize(@s, ref signature);

        start_prank(CheatTarget::One(contract.contract_address), relayer);
        contract
            .permit(
                owner, spender, amount, deadline, signature
            );
        stop_prank(CheatTarget::One(contract.contract_address));

        assert_eq!(contract.allowance(owner, spender), amount);
        assert_eq!(contract.balance_of(owner), SUPPLY);

        start_prank(CheatTarget::One(contract.contract_address), spender);
        contract.transfer_from(owner, spender, amount);
        stop_prank(CheatTarget::One(contract.contract_address));

        assert_eq!(contract.balance_of(owner), SUPPLY - amount);
        assert_eq!(contract.balance_of(spender), amount);
    }

    #[test]
    fn test_domain_separator() {
        let account_class_hash = declare("AccountUpgradeable").unwrap();
        let (owner, _) = deploy_account(account_class_hash);
        let contract = deploy_erc20_permit(NAME(), SYMBOL(), SUPPLY, owner);
        let domain = contract.DOMAIN_SEPARATOR();

        let contract_domain = StarknetDomain {
            name: 'ERC2612', version: 'v1', chain_id: get_tx_info().unbox().chain_id, revision: 1,
        };

        assert_eq!(contract_domain.hash_struct(), domain);
    }

    #[test]
    fn test_wrong_domain_separator() {
        let account_class_hash = declare("AccountUpgradeable").unwrap();
        let (owner, _) = deploy_account(account_class_hash);
        let contract = deploy_erc20_permit(NAME(), SYMBOL(), SUPPLY, owner);
        let domain = contract.DOMAIN_SEPARATOR();

        let contract_domain = StarknetDomain {
            name: 'ERC20', version: 'v2', chain_id: 'SEPOLIA', revision: 1,
        };

        assert_ne!(contract_domain.hash_struct(), domain);
    }

    #[test]
    #[should_panic(expected: ('Permit: Invalid signature',))]
    fn test_permit_with_wrong_domain_separator() {
        let account_class_hash = declare("AccountUpgradeable").unwrap();
        let (owner, key_pair) = deploy_account(account_class_hash);
        let (spender, _) = deploy_account(account_class_hash);
        let contract = deploy_erc20_permit(NAME(), SYMBOL(), SUPPLY, owner);

        let amount = 100;
        let deadline = 'ts10';

        let permit = Permit {
            spender: spender, value: amount, deadline: deadline,
        };

        let contract_domain = StarknetDomain {
            name: 'ERC2612', version: 'v1', chain_id: 'SEPOLIA', revision: 1,
        };

        let offchain_domain = PoseidonTrait::new();
        let offchain_msg_hash = offchain_domain
            .update_with('StarkNet Message')
            .update_with(STARKNET_DOMAIN_TYPE_HASH)
            .update_with(contract_domain.hash_struct())
            .update_with(permit.hash_struct())
            .finalize();

        let (r, s): (felt252, felt252) = key_pair.sign(offchain_msg_hash);

        let mut signature: Array<felt252> = ArrayTrait::new();
        Serde::serialize(@r, ref signature);
        Serde::serialize(@s, ref signature);

        start_warp(CheatTarget::All, 'ts9');
        contract
            .permit(
                owner, spender, amount, deadline, signature
            );
    }
}
