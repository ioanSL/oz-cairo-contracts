#[cfg(test)]
mod testERC20Permit {
    use core::option::OptionTrait;
use core::array::ArrayTrait;
use core::clone::Clone;
use core::hash::HashStateExTrait;
    use hash::HashStateTrait;
    use openzeppelin::presets::erc2612::ERC2612::SNIP12MetadataImpl;
    use openzeppelin::presets::interfaces::account::AccountUpgradeableABIDispatcher;
    use openzeppelin::tests::utils::constants::{
        NAME, SYMBOL, SUPPLY, OWNER, RECIPIENT
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
    use openzeppelin::utils::serde::SerializedAppend;
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
        let mut constructor_args: Array<felt252> = array![];
        constructor_args.append_serde(name);
        constructor_args.append_serde(symbol);
        constructor_args.append_serde(fixed_supply);
        constructor_args.append_serde(recipient);

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
        let mut constructor_args: Array<felt252> = array![];
        let key_pair = KeyPairTrait::<felt252, felt252>::generate();
        constructor_args.append_serde(key_pair.public_key);

        let (contract_address, _) = contract_hash.deploy(@constructor_args).unwrap();

        return (contract_address, key_pair);
    }

    fn generate_signature(
        owner: ContractAddress, spender: ContractAddress, amount: u256, nonce: felt252, deadline: u128,
        key_pair: KeyPair<felt252, felt252>
    ) -> Array<felt252> {
        let permit = Permit {
            owner: owner, spender: spender, value: amount, nonce: nonce, deadline: deadline,
        };

        let msg_hash = permit.get_message_hash(owner);
        let (r, s): (felt252, felt252) = key_pair.sign(msg_hash);

        let mut signature: Array<felt252> = array![];
        signature.append_serde(r);
        signature.append_serde(s);

        return signature;
    }

    fn permit_setup() -> (ContractAddress, KeyPair<felt252, felt252>, ContractAddress, ContractAddress, ERC20PermitABIDispatcher, u256, u128) {
        let account_class_hash = declare("AccountUpgradeable").unwrap();
        let (owner, key_pair) = deploy_account(account_class_hash);
        let (spender, _) = deploy_account(account_class_hash);
        let (relayer, _) = deploy_account(account_class_hash);
        let contract = deploy_erc20_permit(NAME(), SYMBOL(), SUPPLY, owner);
        let deadline = 'ts10';
        let amount = 100;

        return (owner, key_pair, spender, relayer, contract, amount, deadline);
    }

    #[test]
    #[should_panic(expected: ('Permit: Expired deadline',))]
    fn test_permit_expired_deadline() {
        let contract = deploy_erc20_permit(NAME(), SYMBOL(), SUPPLY, OWNER());

        let deadline = 'ts9';
        let amount = 100;
        let signature: Array<felt252> = array![];
        start_warp(CheatTarget::All, 'ts10');
        contract.permit(OWNER(), RECIPIENT(), amount, deadline, signature);
    }

    #[test]
    #[should_panic(expected: ('Permit: Invalid signature',))]
    fn test_permit_invalid_signature() {
        let (owner, _, spender, _, contract, amount, deadline) = permit_setup();

        let signature: Array<felt252> = array![];
        start_warp(CheatTarget::All, 'ts9');
        contract
            .permit(
                owner, spender, amount, deadline, signature
            );
    }

    #[test]
    fn test_permit() {
        let (owner, key_pair, spender, relayer, contract, amount, deadline) = permit_setup();
        let nonce = 0;
        let signature = generate_signature(owner, spender, amount, nonce, deadline, key_pair);

        start_prank(CheatTarget::One(contract.contract_address), relayer);
        contract
            .permit(
                owner, spender, amount, deadline, signature
            );
        stop_prank(CheatTarget::One(contract.contract_address));

        let spender_allowance = contract.allowance(owner, spender);
        let owner_balance = contract.balance_of(owner);

        assert_eq!(spender_allowance, amount);
        assert_eq!(owner_balance, SUPPLY);

        start_prank(CheatTarget::One(contract.contract_address), spender);
        contract.transfer_from(owner, spender, amount);
        stop_prank(CheatTarget::One(contract.contract_address));

        let owner_new_balance = contract.balance_of(owner);
        let spender_new_balance = contract.balance_of(spender);

        assert_eq!(owner_new_balance, SUPPLY - amount);
        assert_eq!(spender_new_balance, amount);
    }

    #[test]
    #[should_panic(expected: ('Permit: Invalid signature',))]
    fn test_permit_duplicated_signature() {
        let (owner, key_pair, spender, relayer, contract, amount, deadline) = permit_setup();
        let nonce = 0;
        let signature = generate_signature(owner, spender, amount, nonce, deadline, key_pair);

        start_prank(CheatTarget::One(contract.contract_address), relayer);
        contract
            .permit(
                owner, spender, amount, deadline, signature.clone()
            );
        stop_prank(CheatTarget::One(contract.contract_address));

        start_prank(CheatTarget::One(contract.contract_address), relayer);
        contract
            .permit(
                owner, spender, amount, deadline, signature
            );
        stop_prank(CheatTarget::One(contract.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Permit: Invalid signature',))]
    fn test_permit_invalid_signature_s() {
        let (owner, key_pair, spender, relayer, contract, amount, deadline) = permit_setup();
        let nonce = 0;
        let mut signature = generate_signature(owner, spender, amount, nonce, deadline, key_pair);

        signature.pop_front().unwrap();
        signature.append(0x0987);
        //[r, s] = signature[0x..., 0x0987]

        start_prank(CheatTarget::One(contract.contract_address), relayer);
        contract
            .permit(
                owner, spender, amount, deadline, signature.clone()
            );
        stop_prank(CheatTarget::One(contract.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Permit: Invalid signature',))]
    fn test_permit_invalid_signature_r() {
        let (owner, key_pair, spender, relayer, contract, amount, deadline) = permit_setup();
        let nonce = 0;
        let mut signature = generate_signature(owner, spender, amount, nonce, deadline, key_pair);

        let s = signature.pop_front().unwrap();
        signature.pop_front().unwrap();
        signature.append(0x0987);
        signature.append(s);
        //[r, s] = signature[0x0987, 0x...]

        start_prank(CheatTarget::One(contract.contract_address), relayer);
        contract
            .permit(
                owner, spender, amount, deadline, signature.clone()
            );
        stop_prank(CheatTarget::One(contract.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Permit: Invalid signature',))]
    fn test_permit_invalid_signature_extra() {
        let (owner, key_pair, spender, relayer, contract, amount, deadline) = permit_setup();
        let nonce = 0;
        let mut signature = generate_signature(owner, spender, amount, nonce, deadline, key_pair);

        signature.append(0x1234);
        //[r, s] = signature[0x.., 0x..., 0x1234]

        start_prank(CheatTarget::One(contract.contract_address), relayer);
        contract
            .permit(
                owner, spender, amount, deadline, signature.clone()
            );
        stop_prank(CheatTarget::One(contract.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Permit: Invalid signature',))]
    fn test_permit_wrong_nonce() {
        let (owner, key_pair, spender, relayer, contract, amount, deadline) = permit_setup();
        let nonce = 300;
        let signature = generate_signature(owner, spender, amount, nonce, deadline, key_pair);

        start_prank(CheatTarget::One(contract.contract_address), relayer);
        contract
            .permit(
                owner, spender, amount, deadline, signature
            );
        stop_prank(CheatTarget::One(contract.contract_address));

    }

    #[test]
    fn test_domain_separator() {
        let (_, _, _, _, contract, _, _) = permit_setup();
        let domain = contract.DOMAIN_SEPARATOR();

        let contract_domain = StarknetDomain {
            name: 'DAPP_NAME', version: 'DAPP_VERSION', chain_id: get_tx_info().unbox().chain_id, revision: 1,
        };

        let contract_domain_hash = contract_domain.hash_struct();

        assert_eq!(contract_domain_hash, domain);
    }

    #[test]
    fn test_wrong_domain_separator() {
        let (_, _, _, _, contract, _, _) = permit_setup();
        let domain = contract.DOMAIN_SEPARATOR();

        let contract_domain = StarknetDomain {
            name: 'ERC20', version: 'v2', chain_id: 'SEPOLIA', revision: 1,
        };

        assert_ne!(contract_domain.hash_struct(), domain);
    }

    #[test]
    #[should_panic(expected: ('Permit: Invalid signature',))]
    fn test_permit_with_wrong_domain_separator() {
        let (owner, key_pair, spender, _, contract, amount, deadline) = permit_setup();

        let permit = Permit {
            owner: owner, spender: spender, value: amount, nonce: 0, deadline: deadline,
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

        let mut signature: Array<felt252> = array![];
        signature.append_serde(r);
        signature.append_serde(s);

        start_warp(CheatTarget::All, 'ts9');
        contract
            .permit(
                owner, spender, amount, deadline, signature
            );
    }
}
