use core::hash::HashStateExTrait;
use hash::{HashStateTrait, Hash};
use openzeppelin::utils::cryptography::snip12::{
    OffchainMessageHash, StructHash, SNIP12Metadata, STARKNET_DOMAIN_TYPE_HASH, StarknetDomain
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

    fn nonces(self: @TState, owner: ContractAddress) -> felt252;

    fn DOMAIN_SEPARATOR(self: @TState) -> felt252;
}

#[starknet::component]
mod ERC20PermitComponent {
    use openzeppelin::account::dual_account::{DualCaseAccount, DualCaseAccountABI};
    use openzeppelin::token::erc20::interface::IERC20;
    use openzeppelin::token::erc20::{
        ERC20Component, ERC20Component::InternalImpl as ERC20InternalTrait
    };
    use openzeppelin::utils::cryptography::interface::INonces;
    use openzeppelin::utils::cryptography::nonces::NoncesComponent::InternalTrait as NoncesInternalTrait;
    use openzeppelin::utils::cryptography::nonces::NoncesComponent;

    use openzeppelin::utils::cryptography::snip12::StructHash;
    use starknet::{get_block_timestamp, get_tx_info};

    use super::{
        HashStateTrait, Hash, StarknetDomain, ContractAddress, IPermit, Permit, OffchainMessageHash,
        SNIP12Metadata, STARKNET_DOMAIN_TYPE_HASH, PoseidonTrait, HashStateExTrait, PERMIT_TYPE_HASH
    };


    #[storage]
    struct Storage {
        Permit_nonces: LegacyMap<ContractAddress, felt252>
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {}


    mod Errors {
        const INVALID_SIGNATURE: felt252 = 'Permit: Invalid signature';
        const INVALID_DEADLINE: felt252 = 'Permit: Expired deadline';
        const INVALID_NONCE: felt252 = 'Permit: Invalid nonce';
    }

    #[embeddable_as(ERC20PermitImpl)]
    impl ERC20Permit<
        TContractState,
        +HasComponent<TContractState>,
        impl ERC20: ERC20Component::HasComponent<TContractState>,
        +ERC20Component::ERC20HooksTrait<TContractState>,
        +SNIP12Metadata,
        +Drop<TContractState>
    > of IPermit<ComponentState<TContractState>> {
        ///
        /// Allows the owner of the token to approve the spender to transfer a specified amount of tokens on their behalf.
        ///
        /// @param self The reference to the ERC20Permit contract state.
        /// @param owner The address of the token owner.
        /// @param spender The address of the spender.
        /// @param value The amount of tokens to be approved for transfer.
        /// @param deadline The deadline timestamp until which the permit is valid.
        /// @param signature The cryptographic signature of the permit.
        ///
        fn permit(
            ref self: ComponentState<TContractState>,
            owner: ContractAddress,
            spender: ContractAddress,
            value: u256,
            deadline: u128,
            signature: Array<felt252>
        ) {
            assert(get_block_timestamp().into() <= deadline, Errors::INVALID_DEADLINE);

            let nonce = self.nonces(owner);
            self._use_nonce(owner, nonce);

            let permit = Permit { owner, spender, value, nonce, deadline};
            let is_valid_signature = self._validate_signature(permit, signature);
            assert(is_valid_signature, Errors::INVALID_SIGNATURE);
            
            let mut erc20_component = get_dep_component_mut!(ref self, ERC20);
            erc20_component._approve(owner, spender, value);
        }

        /// 
        /// Retrieves the nonce value for a specific owner.
        /// 
        /// @param owner The address of the owner for which to retrieve the nonce.
        /// @return The nonce value associated with the owner.
        /// 
        fn nonces(self: @ComponentState<TContractState>, owner: ContractAddress) -> felt252 {
            let nonce = self.Permit_nonces.read(owner);
            return nonce;
        }

        ///
        /// Returns the domain separator for the ERC20 permit extension.
        ///
        /// @return The domain separator value as a felt252.
        ///
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

    #[generate_trait]
    impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        +SNIP12Metadata,
    > of InternalImplTrait<TContractState> {

        ///
        /// Function to use a nonce for a specific owner in the ERC20 permit extension.
        ///
        /// @param owner The address of the owner for whom the nonce is being used.
        /// @param nonce The nonce value to be used.
        /// @return The current nonce value associated with the owner.
        /// 
        fn _use_nonce(ref self: ComponentState<TContractState>, owner: ContractAddress, nonce: felt252) -> felt252 {
            let current = self.Permit_nonces.read(owner);
            self.Permit_nonces.write(owner, nonce + 1);
            assert(nonce == current, Errors::INVALID_NONCE);

            return nonce;
        }

        /// 
        /// Validates the signature of a permit.
        /// 
        /// @param permit The permit struct to validate.
        /// @param signature The signature to validate.
        /// @return True if the signature is valid, false otherwise.
        /// 
        fn _validate_signature(
            self: @ComponentState<TContractState>,
            permit: Permit,
            signature: Array<felt252>
        ) -> bool {
            let hash = permit.get_message_hash(permit.owner);
            let is_valid_signature_felt = DualCaseAccount { contract_address: permit.owner }
                .is_valid_signature(hash, signature);

            return is_valid_signature_felt == starknet::VALIDATED
                || is_valid_signature_felt == 1;
        }
    }
}


const PERMIT_TYPE_HASH: felt252 =
    selector!(
        "\"Permit\"(\"owner\":\"ContractAddress\",\"spender\":\"ContractAddress\",\"value\":\"u256\",\"nonce\":\"felt252\",\"deadline\":\"u128\")\"u256\"(\"low\":\"felt\",\"high\":\"felt\")"
    );


///
/// @title Permit
/// @dev This struct represents a permit for ERC20 token transfers.
/// It contains information about the spender, the value, and the deadline.
///
#[derive(Copy, Drop, Hash)]
struct Permit {
    owner: ContractAddress,
    spender: ContractAddress,
    value: u256,
    nonce: felt252,
    deadline: u128,
}

impl StructHashPermit of StructHash<Permit> {
    fn hash_struct(self: @Permit) -> felt252 {
        let hash_state = PoseidonTrait::new();
        hash_state.update_with(PERMIT_TYPE_HASH).update_with(*self).finalize()
    }
}
