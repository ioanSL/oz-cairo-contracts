%lang starknet
%builtins pedersen range_check ecdsa

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.starknet.common.syscalls import get_caller_address
from starkware.starknet.common.storage import Storage
from starkware.cairo.common.math import assert_nn_le

#
# Storage
#

@storage_var
func owner(token_id: felt, token_no: felt) -> (res: felt):
end

@storage_var
func balances(owner: felt, token_id: felt) -> (res: felt):
end

@storage_var
func token_approvals(token_id: felt, token_no: felt) -> (res: felt):
end

@storage_var
func operator_approvals(owner: felt, operator: felt) -> (res: felt):
end

@storage_var
func initialized() -> (res : felt):
end

@storage_var
func total_supply(token_id : felt) -> (res : felt):
end

@storage_var
func  max_token_id(token_id: felt) ->  (res: felt):
end

################ Now it's felt* maybe after string will be implemented on cairo
@storage_var
func contract_uri() -> (res: felt*):
end

#Support interface !!
#
#
#

#### fonction uri --> after !!!!

#
# Constructor
#

@constructor
func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        recipient : felt, token_id_len : felt, token_id : felt*, amount_len : felt, amount : felt*):
    # get_caller_address() returns '0' in the constructor;
    # therefore, recipient parameter is included
    _mint_batch(recipient, token_id_len, token_id, amount_len, amount)
    return ()
end


#
# Initializer
#

@external
func initialize{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}():
    let (_initialized) = initialized.read()
    assert _initialized = 0
    initialized.write(1)

    let (sender) = get_caller_address()
    _mint(sender, 1, 1000)
    return ()
end

@external
func initialize_batch{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
        token_id_len : felt, token_id : felt*, amount_len : felt, amount : felt*):
    let (_initialized) = initialized.read()
    assert _initialized = 0
    initialized.write(1)

    let (sender) = get_caller_address()
    _mint_batch(sender, token_id_len, token_id, amount_len, amount)
    return ()
end

func _mint{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
        recipient : felt, token_id : felt, amount : felt) -> ():
    let (res) = balances.read(owner=recipient, token_id=token_id)
    balances.write(recipient, token_id, res + amount)

    let (supply) = total_supply.read(token_id=token_id)
    total_supply.write(token_id, supply + amount)
    return ()
end

func _mint_batch{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
        recipient : felt, token_id_len : felt, token_id : felt*, amount_len : felt,
        amount : felt*) -> ():
    assert token_id_len = amount_len
    if token_id_len == 0:
        return ()
    end
    _mint(recipient, token_id[0], amount[0])
    return _mint_batch(
        recipient=recipient,
        token_id_len=token_id_len - 1,
        token_id=token_id + 1,
        amount_len=amount_len - 1,
        amount=amount + 1)
end

#
# Getters
#

@view
func balance_of{
        pedersen_ptr: HashBuiltin*,
        syscall_ptr : felt*, 
        range_check_ptr
    } (owner: felt, token_id: felt) -> (res: felt):
    let (res) = balance.read(owner=owner, token_id=id)
    return (res)
end

@view
func balance_of_batch{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
        owner_len : felt, owner : felt*, token_id_len : felt, token_id : felt*) -> (res : felt):
    assert owner_len = token_id_len
    if owner_len == 0:
        return (0)
    end
    balance_of(owner[0], token_id[0])
    return balance_of_batch(
        owner_len=owner_len - 1,
        owner=owner + 1,
        token_id_len=token_id_len - 1,
        token_id=token_id + 1)
end

# function for testing purposes
@view
func get_total_supply{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
        token_id : felt) -> (res : felt):
    let (supply) = total_supply.read(token_id=token_id)
    return (supply)
end

#
# Approvals
#

@view
func owner_of{
        pedersen_ptr: HashBuiltin*,
        syscall_ptr : felt*, 
        range_check_ptr
    } (token_id: felt, token_no: felt) -> (res: felt):
    let (res) = owner.read(token_id=token_id, token_no=token_no)
    return (res)
end

# @external
# func set_approval_for_all{
    # storage_ptr: Storage*,
    # pedersen_ptr: HashBuiltin*,
    # range_check_ptr
    # } (operator: felt, approved: felt):
    # _set_approval_for_all(account=get_caller_address(),operator, approved)
    # return ()
# end


@view
func is_approved_for_all{storage_ptr: Storage*,pedersen_ptr: HashBuiltin*,range_check_ptr} (account: felt, operator: felt) -> (res: felt):
    let (_res) = operator_approvals.read(owner=account, operator)
    return (res=_res)
end

func _set_approval_for_all{
    storage_ptr: Storage*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr
    } (account: felt, operator: felt, approved: felt):
    if account == operator:
        return()
    end
    operator_approvals.write(owner=account, operator, approved) 
    return ()
end

#
# Transfer
#

func _transfer{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
        sender : felt, recipient : felt, token_id : felt, amount : felt):
    # validate sender has enough funds
    let (sender_balance) = balances.read(owner=sender, token_id=token_id)
    assert_nn_le(amount, sender_balance)

    # substract from sender
    balances.write(sender, token_id, sender_balance - amount)

    # add to recipient
    let (res) = balances.read(owner=recipient, token_id=token_id)
    balances.write(recipient, token_id, res + amount)
    return ()
end

@external
func transfer{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
        recipient : felt, token_id : felt, amount : felt):
    let (sender) = get_caller_address()
    _transfer(sender, recipient, token_id, amount)
    return ()
end

@external
func transfer_batch{pedersen_ptr : HashBuiltin*, syscall_ptr : felt*, range_check_ptr}(
        recipient : felt, token_id_len : felt, token_id : felt*, amount_len : felt, amount : felt*):
    let (sender) = get_caller_address()
    assert token_id_len = amount_len
    if token_id_len == 0:
        return ()
    end
    _transfer(sender, recipient, token_id[0], amount[0])
    return transfer_batch(
        recipient=recipient,
        token_id_len=token_id_len - 1,
        token_id=token_id + 1,
        amount_len=amount_len - 1,
        amount=amount + 1)
end

# func transfer_from
# func batch_transfer_from