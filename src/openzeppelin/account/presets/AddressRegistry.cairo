// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts for Cairo v0.3.2 (account/presets/AddressRegistry.cairo)

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_caller_address

@storage_var
func L1_address(L2_address: felt) -> (res: felt) {
}

@external
func get_L1_address{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    L2_address: felt
) -> (address: felt) {
    let (address) = L1_address.read(L2_address);
    return (address=address);
}

@external
func set_L1_address{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    new_L1_address: felt
) {
    let (caller) = get_caller_address();
    L1_address.write(caller, new_L1_address);
    return ();
}
