%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.starknet.common.syscalls import get_caller_address
from starkware.cairo.common.math import assert_not_zero
from starkware.cairo.common.uint256 import Uint256, uint256_check

from contracts.utils.safemath import (
    uint256_checked_add,
    uint256_checked_sub_le
)

#
# Storage
#

@storage_var
func ERC20_name_() -> (name: felt):
end

@storage_var
func ERC20_symbol_() -> (symbol: felt):
end

@storage_var
func ERC20_decimals_() -> (decimals: felt):
end

@storage_var
func ERC20_total_supply() -> (total_supply: Uint256):
end

@storage_var
func ERC20_balances(account: felt) -> (balance: Uint256):
end

@storage_var
func ERC20_allowances(owner: felt, spender: felt) -> (allowance: Uint256):
end

#
# Constructor
#

func ERC20_initializer{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(
        name: felt,
        symbol: felt,
        initial_supply: Uint256,
        recipient: felt
    ):
    ERC20_name_.write(name)
    ERC20_symbol_.write(symbol)
    ERC20_decimals_.write(18)
    ERC20_mint(recipient, initial_supply)
    return ()
end

func ERC20_name{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (name: felt):
    let (name) = ERC20_name_.read()
    return (name)
end

func ERC20_symbol{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (symbol: felt):
    let (symbol) = ERC20_symbol_.read()
    return (symbol)
end

func ERC20_totalSupply{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (totalSupply: Uint256):
    let (totalSupply: Uint256) = ERC20_total_supply.read()
    return (totalSupply)
end

func ERC20_decimals{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (decimals: felt):
    let (decimals) = ERC20_decimals_.read()
    return (decimals)
end

func ERC20_balanceOf{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(account: felt) -> (balance: Uint256):
    let (balance: Uint256) = ERC20_balances.read(account)
    return (balance)
end

func ERC20_allowance{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(owner: felt, spender: felt) -> (remaining: Uint256):
    let (remaining: Uint256) = ERC20_allowances.read(owner, spender)
    return (remaining)
end

func ERC20_transfer{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(recipient: felt, amount: Uint256):
    let (sender) = get_caller_address()
    _transfer(sender, recipient, amount)
    return ()
end

func ERC20_transferFrom{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(
        sender: felt, 
        recipient: felt, 
        amount: Uint256
    ) -> ():
    alloc_locals
    let (local caller) = get_caller_address()
    let (local caller_allowance: Uint256) = ERC20_allowances.read(owner=sender, spender=caller)

    _transfer(sender, recipient, amount)

    # subtract allowance
    # safemath validates amount <= caller_allowance 
    with_attr error_message("ERC20_base: transfer amount exceeds balance"):
        let (new_allowance: Uint256) = uint256_checked_sub_le(caller_allowance, amount)
    end

    ERC20_allowances.write(sender, caller, new_allowance)
    return ()
end

func ERC20_approve{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(spender: felt, amount: Uint256):
    let (caller) = get_caller_address()
    with_attr error_message("ERC20_base: transfer from the zero address"):
        assert_not_zero(caller)
    end

    with_attr error_message("ERC20_base: transfer to the zero address"):
        assert_not_zero(spender)
    end

    with_attr error_message("ERC20_base: invalid uint256 transfer amount"):
        uint256_check(amount)
    end

    ERC20_allowances.write(caller, spender, amount)
    return ()
end

func ERC20_increaseAllowance{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(spender: felt, added_value: Uint256) -> ():
    alloc_locals
    with_attr error_message("ERC20_base: invalid uint256 amount"):
        uint256_check(added_value)
    end

    let (local caller) = get_caller_address()
    let (local current_allowance: Uint256) = ERC20_allowances.read(caller, spender)

    # add allowance
    # safemath checks for overflow
    with_attr error_message("ERC20_base: increase allowance overflow"):
        let (local new_allowance: Uint256) = uint256_checked_add(current_allowance, added_value)
    end

    ERC20_approve(spender, new_allowance)
    return ()
end

func ERC20_decreaseAllowance{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(spender: felt, subtracted_value: Uint256) -> ():
    alloc_locals
    uint256_check(subtracted_value)
    let (local caller) = get_caller_address()
    let (local current_allowance: Uint256) = ERC20_allowances.read(owner=caller, spender=spender)
    # safemath validates new_allowance < current_allowance  

    with_attr error_message("ERC20_base: decreased allowance under zero"):
        let (local new_allowance: Uint256) = uint256_checked_sub_le(current_allowance, subtracted_value)
    end

    ERC20_approve(spender, new_allowance)
    return ()
end

func ERC20_mint{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(recipient: felt, amount: Uint256):
    alloc_locals
    with_attr error_message("ERC20_base: transfer to the zero address"):
        assert_not_zero(recipient)
    end

    with_attr error_message("ERC20_base: invalid uint256 amount"):
        uint256_check(amount)
    end

    let (balance: Uint256) = ERC20_balances.read(account=recipient)
    # overflow is not possible because sum is guaranteed to be less than total supply
    # which we check for overflow below
    with_attr error_message("ERC20_base: user balance overflow"):
        let (new_balance) = uint256_checked_add(balance, amount)
    end

    ERC20_balances.write(recipient, new_balance)

    let (local supply: Uint256) = ERC20_total_supply.read()

    with_attr error_message("ERC20_base: mint amount overflow"):
        let (local new_supply: Uint256) = uint256_checked_add(supply, amount)
    end

    ERC20_total_supply.write(new_supply)
    return ()
end

func ERC20_burn{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(account: felt, amount: Uint256):
    alloc_locals
    with_attr error_message("ERC20_base: burn from the zero address"):
        assert_not_zero(account)
    end

    with_attr error_message("ERC20_base: invalid uint256 burn amount"):
        uint256_check(amount)
    end

    let (balance: Uint256) = ERC20_balances.read(account)
    
    # safemath validates amount <= balance
    with_attr error_message("ERC20_base: burn amount exceeds balance"):
        let (new_balance: Uint256) = uint256_checked_sub_le(balance, amount)
    end

    ERC20_balances.write(account, new_balance)

    let (supply: Uint256) = ERC20_total_supply.read()
    let (new_supply: Uint256) = uint256_checked_sub_le(supply, amount)

    ERC20_total_supply.write(new_supply)
    return ()
end

#
# Internal
#

func _transfer{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(sender: felt, recipient: felt, amount: Uint256):
    alloc_locals
    with_attr error_message("ERC20_base: transfer from the zero address"):
        assert_not_zero(sender)
    end

    with_attr error_message("ERC20_base: transfer to the zero address"):
        assert_not_zero(recipient)
    end

    with_attr error_message("ERC20_base: invalid uint256 transfer amount"):
        uint256_check(amount) # almost surely not needed, might remove after confirmation
    end

    let (local sender_balance: Uint256) = ERC20_balances.read(account=sender)

    # subtract from sender
    # safemath validates amount <= sender_balance
    with_attr error_message("ERC20_base: transfer amount exceeds balance"):
        let (new_sender_balance: Uint256) = uint256_checked_sub_le(sender_balance, amount)
    end
    
    ERC20_balances.write(sender, new_sender_balance)

    # add to recipient
    let (recipient_balance: Uint256) = ERC20_balances.read(account=recipient)
    # overflow is not possible because sum is guaranteed by mint to be less than total supply
    let (new_recipient_balance) = uint256_checked_add(recipient_balance, amount)
    ERC20_balances.write(recipient, new_recipient_balance)
    return ()
end
