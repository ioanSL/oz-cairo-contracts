use core::hash::HashStateExTrait;
use hash::{HashStateTrait, Hash};
use openzeppelin::utils::cryptography::snip12::{OffchainMessageHash, StructHash, SNIP12Metadata};
use poseidon::PoseidonTrait;
use starknet::ContractAddress;

#[starknet::interface]
trait IPermit<TState> {
    fn permit(
        ref self: TState,
        owner: ContractAddress,
        spender: ContractAddress,
        value: u256,
        deadline: u64,
        signature: Array<felt252>
    );

    fn nonces(self: @TState, owner: ContractAddress) -> felt252;

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
    use super::{ContractAddress, IPermit, Permit, OffchainMessageHash, SNIP12Metadata};

    #[storage]
    struct Storage {}

    mod Errors {
        const INVALID_SIGNATURE: felt252 = 'Permit: Invalid signature';
        const INVALID_DEADLINE: felt252 = 'Permit: Expired deadline';
        const INVALID_NONCE: felt252 = 'Permit: Invalid nonce';
        const INVALID_OWNER: felt252 = 'Permit: Invalid owner';
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
            deadline: u64,
            signature: Array<felt252>
        ) {
            assert(get_block_timestamp() > deadline, Errors::INVALID_DEADLINE);
            
            let mut nonces_component = get_dep_component_mut!(ref self, Nonces);
            let nonce = self.nonces(owner);
            nonces_component.use_checked_nonce(owner, nonce);

            let permit = Permit {
                owner,
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

        fn nonces(self: @ComponentState<TContractState>, owner: ContractAddress) -> felt252 {
            let nonces_component = get_dep_component!(self, Nonces);
            return nonces_component.nonces(owner);
        }

        fn DOMAIN_SEPARATOR(self: @ComponentState<TContractState>) -> felt252 {
            return 0;
        }
    }
}


// sn_keccak("\"Permit\"(\"owner\":\"ContractAddress\",\"spender\":\"ContractAddress\",\"value\":\"u256\",\"deadline\":\"u128\")\"u256\"(\"low\":\"felt\",\"high\":\"felt\")")
// Result of computing off-cahin the above string using StarknetJS
const PERMIT_TYPE_HASH: felt252 = 
    0x2c6b40a68694b0c81b94622be3270b572c66062829ef49ce2ceca6735ac4948;

#[derive(Copy, Drop, Hash)]
struct Permit {
    owner: ContractAddress,
    spender: ContractAddress,
    value: u256,
    deadline: u64,
}

impl StructHashImpl of StructHash<Permit> {
    fn hash_struct(self: @Permit) -> felt252 {
        let hash_state = PoseidonTrait::new();
        hash_state.update_with(PERMIT_TYPE_HASH).update_with(*self).finalize()
    }
}