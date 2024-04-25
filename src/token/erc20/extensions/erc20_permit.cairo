use core::hash::HashStateExTrait;
use hash::{HashStateTrait, Hash};
use openzeppelin::utils::cryptography::snip12::{
    OffchainMessageHash, 
    StructHash, 
    SNIP12Metadata, 
    STARKNET_DOMAIN_TYPE_HASH
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
    use starknet::get_block_timestamp;
    use openzeppelin::account::dual_account::{DualCaseAccount, DualCaseAccountABI};
    use openzeppelin::utils::cryptography::interface::INonces;
    use openzeppelin::token::erc20::{ERC20Component, ERC20Component::InternalImpl as ERC20InternalTrait};
    use openzeppelin::token::erc20::interface::IERC20;
    use openzeppelin::utils::cryptography::nonces::NoncesComponent::InternalTrait as NoncesInternalTrait;
    use openzeppelin::utils::cryptography::nonces::NoncesComponent;
    use super::{ContractAddress, IPermit, Permit, OffchainMessageHash, SNIP12Metadata, STARKNET_DOMAIN_TYPE_HASH};

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

        fn DOMAIN_SEPARATOR(self: @ComponentState<TContractState>) -> felt252 {
            return STARKNET_DOMAIN_TYPE_HASH;
        }
    }
}


// sn_keccak("\"Permit\"(\"spender\":\"ContractAddress\",\"value\":\"u256\",\"deadline\":\"u128\")\"u256\"(\"low\":\"felt\",\"high\":\"felt\")")
// Result of computing off-cahin the above string using StarknetJS
const PERMIT_TYPE_HASH: felt252 = 
    selector!("Permit(spender:ContractAddress,value:u256,deadline:u128)u256(low:felt,high:felt)");

// sn_keccak("\"u256\"(\"low\":\"felt\",\"high\":\"felt\)")
// Result of computing off-cahin the above string using StarknetJS
const U256_TYPE_HASH: felt252 =
    selector!("u256(low:felt,high:felt)");


#[derive(Copy, Drop, Hash)]
struct Permit {
    spender: ContractAddress,
    value: u256,
    deadline: u128,
}

impl StructHashImpl of StructHash<Permit> {
    fn hash_struct(self: @Permit) -> felt252 {
        let hash_state = PoseidonTrait::new();
        hash_state
            .update_with(PERMIT_TYPE_HASH)
            .update_with(*self.spender)
            .update_with(self.value.hash_struct())
            .update_with(*self.deadline)
            .finalize()
    }
}

impl StructHashU256 of StructHash<u256> {
    fn hash_struct(self: @u256) -> felt252 {
        let state = PoseidonTrait::new();
        state
            .update_with(U256_TYPE_HASH)
            .update_with(*self)
            .finalize()
    }
}