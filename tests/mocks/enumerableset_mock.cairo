# SPDX-License-Identifier: MIT

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from openzeppelin.utils.structs.enumerableset import (
    EnumerableSet_add, EnumerableSet_remove, EnumerableSet_contains, EnumerableSet_length,
    EnumerableSet_at, EnumerableSet_values)

const SET_ID = 0

@external
func add{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(value : felt) -> (
        success : felt):
    let (success) = EnumerableSet_add(set_id=SET_ID, value=value)
    return (success=success)
end

@external
func remove{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(value : felt) -> (
        success : felt):
    let (success) = EnumerableSet_remove(set_id=SET_ID, value=value)
    return (success=success)
end

@view
func contains{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(value : felt) -> (
        contains : felt):
    let (contains) = EnumerableSet_contains(set_id=SET_ID, value=value)
    return (contains=contains)
end

@view
func length{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (length : felt):
    let (length) = EnumerableSet_length(set_id=SET_ID)
    return (length=length)
end

@view
func at{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(index : felt) -> (
        res : felt):
    let (res) = EnumerableSet_at(set_id=SET_ID, index=index)
    return (res=res)
end

@view
func values{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
        res_len : felt, res : felt*):
    let (res) = EnumerableSet_values(set_id=SET_ID)
    let (length) = EnumerableSet_length(set_id=SET_ID)
    return (res_len=length, res=res)
end
