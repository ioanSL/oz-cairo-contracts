use core::hash::HashStateExTrait;
use hash::{HashStateTrait, Hash};
use openzeppelin::utils::cryptography::snip12::{
    OffchainMessageHash, 
    StructHash, 
    SNIP12Metadata, 
    STARKNET_DOMAIN_TYPE_HASH,
    StarknetDomain
};
use poseidon::PoseidonTrait;
use starknet::ContractAddress;

#[starknet::interface]
trait IPermit<TState> {
    fn permit(
        ref self: TState,
        owner: ContractAddress,
        spender: ContractAddress,
        value: u256,
        deadline: u128,
        signature: Array<felt252>
    );

    fn DOMAIN_SEPARATOR(self: @TState) -> felt252;
}

#[starknet::component]
mod ERC20PermitComponent {
    use core::traits::Destruct;
    use starknet::{get_block_timestamp, get_tx_info};

    use openzeppelin::utils::cryptography::snip12::StructHash;
    use openzeppelin::account::dual_account::{DualCaseAccount, DualCaseAccountABI};
    use openzeppelin::utils::cryptography::interface::INonces;
    use openzeppelin::token::erc20::{ERC20Component, ERC20Component::InternalImpl as ERC20InternalTrait};
    use openzeppelin::token::erc20::interface::IERC20;
    use openzeppelin::utils::cryptography::nonces::NoncesComponent::InternalTrait as NoncesInternalTrait;
    use openzeppelin::utils::cryptography::nonces::NoncesComponent;
    
    use super::{
        HashStateTrait, Hash, StarknetDomain, ContractAddress, IPermit, Permit, OffchainMessageHash, SNIP12Metadata, 
        STARKNET_DOMAIN_TYPE_HASH, PoseidonTrait, HashStateExTrait, PERMIT_TYPE_HASH
    };


    #[storage]
    struct Storage {}

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {}
    

    mod Errors {
        const INVALID_SIGNATURE: felt252 = 'Permit: Invalid signature';
        const INVALID_DEADLINE: felt252 = 'Permit: Expired deadline';
    }

    #[embeddable_as(ERC20PermitImpl)]
    impl ERC20Permit<
        TContractState,
        +HasComponent<TContractState>,
        impl ERC20: ERC20Component::HasComponent<TContractState>,
        +ERC20Component::ERC20HooksTrait<TContractState>,
        impl Nonces: NoncesComponent::HasComponent<TContractState>,
        +SNIP12Metadata,
        +Drop<TContractState>
    > of IPermit<ComponentState<TContractState>> {

        //
        // Allows the owner of the token to approve the spender to transfer a specified amount of tokens on their behalf.
        //
        // @param self The reference to the ERC20Permit contract state.
        // @param owner The address of the token owner.
        // @param spender The address of the spender.
        // @param value The amount of tokens to be approved for transfer.
        // @param deadline The deadline timestamp until which the permit is valid.
        // @param signature The cryptographic signature of the permit.
        //
        fn permit(
            ref self: ComponentState<TContractState>, 
            owner: ContractAddress, 
            spender: ContractAddress, 
            value: u256, 
            deadline: u128,
            signature: Array<felt252>
        ) {
            assert(get_block_timestamp().into() <= deadline, Errors::INVALID_DEADLINE);
            
            let mut nonces_component = get_dep_component_mut!(ref self, Nonces);
            let nonce = nonces_component.nonces(owner);
            nonces_component.use_checked_nonce(owner, nonce);

            let permit = Permit {
                spender, 
                value, 
                deadline,
            };
            let hash = permit.get_message_hash(owner);

            let is_valid_signature_felt = DualCaseAccount { contract_address: owner }
                .is_valid_signature(hash, signature);

            let is_valid_signature = is_valid_signature_felt == starknet::VALIDATED 
                || is_valid_signature_felt == 1;

            assert(is_valid_signature, Errors::INVALID_SIGNATURE);

            let mut erc20_component = get_dep_component_mut!(ref self, ERC20);
            erc20_component._approve(owner, spender, value);
        }

        //
        // Returns the domain separator for the ERC20 permit extension.
        //
        // @param self The reference to the component state of the contract.
        // @return The domain separator value as a felt252.
        //
        fn DOMAIN_SEPARATOR(self: @ComponentState<TContractState>) -> felt252 {
            let component_domain = StarknetDomain {
                name: SNIP12Metadata::name(),
                version: SNIP12Metadata::version(),
                chain_id: get_tx_info().unbox().chain_id,
                revision: 1
            };
            
            return component_domain.hash_struct();
        }
    }
}


const PERMIT_TYPE_HASH: felt252 = 
    selector!("\"Permit\"(\"spender\":\"ContractAddress\",\"value\":\"u256\",\"deadline\":\"u128\")\"u256\"(\"low\":\"felt\",\"high\":\"felt\")");


//
// @title Permit
// @dev This struct represents a permit for ERC20 token transfers.
// It contains information about the spender, the value, and the deadline.
//
#[derive(Copy, Drop, Hash)]
struct Permit {
    spender: ContractAddress,
    value: u256,
    deadline: u128,
}

impl StructHashPermit of StructHash<Permit> {
    fn hash_struct(self: @Permit) -> felt252 {
        let hash_state = PoseidonTrait::new();
        hash_state
            .update_with(PERMIT_TYPE_HASH)
            .update_with(*self)
            .finalize()
    }
}
