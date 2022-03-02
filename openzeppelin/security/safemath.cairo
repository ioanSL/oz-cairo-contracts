# SPDX-License-Identifier: MIT
# OpenZeppelin Cairo Contracts v0.1.0 (security/safemath.cairo)

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.math import assert_not_zero
from starkware.cairo.common.uint256 import (
    Uint256, uint256_check, uint256_add, uint256_sub, uint256_le, uint256_lt
)

# Adds two integers. 
# Reverts if the sum overflows.
func uint256_checked_add{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*, 
        range_check_ptr
    } (a: Uint256, b: Uint256) -> (c: Uint256):
    uint256_check(a)
    uint256_check(b)
    let (c: Uint256, is_overflow) = uint256_add(a, b)
    with_attr error_message("Safemath: addition overflow"):
        assert (is_overflow) = 0
    end
    return (c)
end

# Subtracts two integers.
# Reverts if minuend (`b`) is greater than subtrahend (`a`).
func uint256_checked_sub_le{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*, 
        range_check_ptr
    } (a: Uint256, b: Uint256) -> (c: Uint256):
    alloc_locals
    uint256_check(a)
    uint256_check(b)
    let (is_le) = uint256_le(b, a)
    with_attr error_message("Safemath: minuend is greater than subtrahend"):
        assert_not_zero(is_le)
    end
    let (c: Uint256) = uint256_sub(a, b)
    return (c)
end

# Subtracts two integers.
# Reverts if minuend (`b`) is greater than or equal to subtrahend (`a`).
func uint256_checked_sub_lt{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*, 
        range_check_ptr
    } (a: Uint256, b: Uint256) -> (c: Uint256):
    alloc_locals
    uint256_check(a)
    uint256_check(b)

    let (is_lt) = uint256_lt(b, a)
    with_attr error_message("Safemath: minuend is greater than or equal to subtrahend"):
        assert_not_zero(is_lt)
    end
    let (c: Uint256) = uint256_sub(a, b)
    return (c)
end
