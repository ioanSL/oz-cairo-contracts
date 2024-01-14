// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts for Cairo v0.8.0 (token/erc20/mixins/erc20_metadata_safe_allowance.cairo)

#[starknet::component]
mod ERC20MetadataSafeAllowanceMixin {
    use openzeppelin::token::erc20::ERC20Component::{
        ERC20Impl, ERC20CamelOnlyImpl, ERC20MetadataImpl
    };
    use openzeppelin::token::erc20::ERC20Component::{SafeAllowanceImpl, SafeAllowanceCamelImpl};
    use openzeppelin::token::erc20::ERC20Component;
    use openzeppelin::token::erc20::mixins::interface::IERC20MetadataSafeAllowanceMixin;
    use openzeppelin::token::erc20::mixins::interface;
    use starknet::ContractAddress;

    #[storage]
    struct Storage {}

    #[embeddable_as(ERC20MetadataSafeAllowanceMixinImpl)]
    impl ERC20MetadataSafeAllowanceMixin<
        TContractState,
        +HasComponent<TContractState>,
        impl ERC20: ERC20Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of interface::IERC20MetadataSafeAllowanceMixin<ComponentState<TContractState>> {
        // IERC20
        fn total_supply(self: @ComponentState<TContractState>) -> u256 {
            let erc20 = self.get_erc20();
            erc20.total_supply()
        }

        fn balance_of(self: @ComponentState<TContractState>, account: ContractAddress) -> u256 {
            let erc20 = self.get_erc20();
            erc20.balance_of(account)
        }

        fn allowance(
            self: @ComponentState<TContractState>, owner: ContractAddress, spender: ContractAddress
        ) -> u256 {
            let erc20 = self.get_erc20();
            erc20.allowance(owner, spender)
        }

        fn transfer(
            ref self: ComponentState<TContractState>, recipient: ContractAddress, amount: u256
        ) -> bool {
            let mut erc20 = get_dep_component_mut!(ref self, ERC20);
            erc20.transfer(recipient, amount)
        }

        fn transfer_from(
            ref self: ComponentState<TContractState>,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256
        ) -> bool {
            let mut erc20 = get_dep_component_mut!(ref self, ERC20);
            erc20.transfer_from(sender, recipient, amount)
        }

        fn approve(
            ref self: ComponentState<TContractState>, spender: ContractAddress, amount: u256
        ) -> bool {
            let mut erc20 = get_dep_component_mut!(ref self, ERC20);
            erc20.approve(spender, amount)
        }

        // IERC20Metadata
        fn name(self: @ComponentState<TContractState>) -> felt252 {
            let erc20 = self.get_erc20();
            erc20.name()
        }

        fn symbol(self: @ComponentState<TContractState>) -> felt252 {
            let erc20 = self.get_erc20();
            erc20.symbol()
        }

        fn decimals(self: @ComponentState<TContractState>) -> u8 {
            let erc20 = self.get_erc20();
            erc20.decimals()
        }

        // IERC20SafeAllowance
        fn increase_allowance(
            ref self: ComponentState<TContractState>, spender: ContractAddress, added_value: u256
        ) -> bool {
            let mut erc20 = get_dep_component_mut!(ref self, ERC20);
            erc20.increase_allowance(spender, added_value)
        }

        fn decrease_allowance(
            ref self: ComponentState<TContractState>,
            spender: ContractAddress,
            subtracted_value: u256
        ) -> bool {
            let mut erc20 = get_dep_component_mut!(ref self, ERC20);
            erc20.decrease_allowance(spender, subtracted_value)
        }

        // IERC20CamelOnly
        fn totalSupply(self: @ComponentState<TContractState>) -> u256 {
            let erc20 = self.get_erc20();
            erc20.totalSupply()
        }

        fn balanceOf(self: @ComponentState<TContractState>, account: ContractAddress) -> u256 {
            let erc20 = self.get_erc20();
            erc20.balanceOf(account)
        }

        fn transferFrom(
            ref self: ComponentState<TContractState>,
            sender: ContractAddress,
            recipient: ContractAddress,
            amount: u256
        ) -> bool {
            let mut erc20 = get_dep_component_mut!(ref self, ERC20);
            erc20.transferFrom(sender, recipient, amount)
        }

        // IERC20CamelSafeAllowance
        fn increaseAllowance(
            ref self: ComponentState<TContractState>, spender: ContractAddress, addedValue: u256
        ) -> bool {
            let mut erc20 = get_dep_component_mut!(ref self, ERC20);
            erc20.increaseAllowance(spender, addedValue)
        }

        fn decreaseAllowance(
            ref self: ComponentState<TContractState>,
            spender: ContractAddress,
            subtractedValue: u256
        ) -> bool {
            let mut erc20 = get_dep_component_mut!(ref self, ERC20);
            erc20.decreaseAllowance(spender, subtractedValue)
        }
    }

    #[generate_trait]
    impl GetERC20Impl<
        TContractState,
        +HasComponent<TContractState>,
        +ERC20Component::HasComponent<TContractState>,
        +Drop<TContractState>
    > of GetERC20Trait<TContractState> {
        fn get_erc20(
            self: @ComponentState<TContractState>
        ) -> @ERC20Component::ComponentState::<TContractState> {
            let contract = self.get_contract();
            ERC20Component::HasComponent::<TContractState>::get_component(contract)
        }
    }
}
