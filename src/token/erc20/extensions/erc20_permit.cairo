use starknet::ContractAddress;

#[starknet::interface]
trait IPermit<TState> {
    fn permit(
        ref self: TState,
        owner: ContractAddress,
        spender: ContractAddress,
        value: u256,
        deadline: u64,
        nonce: felt252,
        signature: Array<felt252>
    );

    fn nonces(self: @TState, owner: ContractAddress) -> felt252;

    fn DOMAIN_SEPARATOR(self: @TState) -> felt252;
}

#[starknet::component]
mod ERC20PermitComponent {
    use openzeppelin::utils::cryptography::interface::INonces;
use super::IPermit;
    use openzeppelin::token::erc20::ERC20Component;
    use openzeppelin::token::erc20::interface::IERC20;
    use openzeppelin::utils::cryptography::nonces::NoncesComponent::InternalTrait as NoncesInternalTrait;
    use openzeppelin::utils::cryptography::nonces::NoncesComponent;
    use super::ContractAddress;

    #[storage]
    struct Storage {
        deadline: u64,
    }

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
        +ERC20Component::HasComponent<TContractState>,
        +ERC20Component::ERC20HooksTrait<TContractState>,
        impl Nonces: NoncesComponent::HasComponent<TContractState>,
        +Drop<TContractState>
    > of IPermit<ComponentState<TContractState>> {

        fn permit(
            ref self: ComponentState<TContractState>, 
            owner: ContractAddress, 
            spender: ContractAddress, 
            value: u256, 
            deadline: u64,
            nonce: felt252,
            signature: Array<felt252>
        ) {
            assert(deadline <= self.deadline.read(), Errors::INVALID_DEADLINE);
            assert(owner.is_non_zero(), Errors::INVALID_OWNER);
            let mut nonces_component = get_dep_component_mut!(ref self, Nonces);
            nonces_component.use_checked_nonce(owner, nonce);
            // TODO: Verify signature
            self._permit(spender, value);
        }

        fn nonces(self: @ComponentState<TContractState>, owner: ContractAddress) -> felt252 {
            let nonces_component = get_dep_component!(self, Nonces);
            return nonces_component.nonces(owner);
        }

        fn DOMAIN_SEPARATOR(self: @ComponentState<TContractState>) -> felt252 {
            return 0;
        }
    }

    #[generate_trait]
    impl InternalImpl<
        TContractState,
        +HasComponent<TContractState>,
        impl ERC20: ERC20Component::HasComponent<TContractState>,
        +ERC20Component::ERC20HooksTrait<TContractState>,
        +Drop<TContractState>
    > of InternalTrait<TContractState> {
        fn initializer(
            ref self: ComponentState<TContractState>, 
            deadline: u64
        ) {
            self.deadline.write(deadline);
        }

        fn _permit(
            ref self: ComponentState<TContractState>, 
            spender: ContractAddress, 
            value: u256, 
        ) {
            let mut erc20_component = get_dep_component_mut!(ref self, ERC20);
            erc20_component.approve(spender, value);
        }
    }
}