import pytest
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.public.abi import get_selector_from_name
from signers import MockSigner
from utils import (
    assert_event_emitted,
    assert_revert,
    get_contract_class,
    cached_contract,
    set_block_timestamp,
    from_call_to_call_array,
    flatten_calls,
    timelock_hash_chain,
    to_uint,
    str_to_felt,
    role_repr,
    ZERO_ADDRESS,
    TRUE,
    FALSE
)

signer = MockSigner(123456789987654321)


# first 251 bits of the keccak256 role
TIMELOCK_ADMIN_ROLE = 0x5f58e3a2316349923ce3780f8d587db2d72378aed66a8261c916544fa6846ca
PROPOSER_ROLE = 0x584d52d759b8167ea85b5b15e229930249c790924513d0eae539b0415b40ce6
EXECUTOR_ROLE = 0x6c550798ca4b8d1508b33cfbe10487b49ce46a700d1546bf20eaaf29a8a34f3
CANCELLER_ROLE = 0x7eb21e39388631e00c012cd5d359682a28f1ac8d1272c5b111c9bc042b937bc

# arrays of mock addresses
PROPOSERS = [0x10, 0x11, 0x12]
EXECUTORS = [0x20, 0x21]
CANCELLERS = [0x30]

# selector ids
IERC165_ID = 0x01ffc9a7
IERC721_RECEIVER_ID = 0x150b7a02
IERC1155_RECEIVER_ID = 0x4e2312e0
INVALID_ID = 0xffffffff
UNSUPPORTED_ID = 0xabcd1234
IACCESSCONTROL_ID = 0x7965db0b

MIN_DELAY = 86400
NEW_MIN_DELAY = 21600
BAD_DELAY = 100
FF_PAST_DELAY = MIN_DELAY + 10
AMOUNT = 5
TOKEN = to_uint(5042)
SALT = 5417

# random data (mimicking bytes in Solidity)
DATA = [0x42, 0x89, 0x55]

#
# formatted calls
#


def build_call(address):
    """Return formatted call for `from_call_to_call_array` and hash chain."""
    return [
        [address, "increase_balance", [AMOUNT]]
    ]


def build_batch(address):
    """Return formatted calls for `from_call_to_call_array` and hash chain."""
    return [
        *build_call(address),
        *build_call(address),
        *build_call(address)
    ]


def single_operation(address):
    """Return single callable test operation."""
    return from_call_to_call_array([
        *build_call(address)
    ])


def batched_operations(address):
    """Return batched callable test operations."""
    return from_call_to_call_array([
        *build_batch(address)
    ])

#
# fixtures
#


@pytest.fixture(scope="module")
async def contract_classes():
    account_cls = get_contract_class("Account")
    timelock_cls = get_contract_class("Timelock")
    target_cls = get_contract_class("Contract")
    erc721_cls = get_contract_class('ERC721_Mintable_Burnable')
    mal_target_cls = get_contract_class("TimelockReentrancy")

    return account_cls, timelock_cls, target_cls, erc721_cls, mal_target_cls


@pytest.fixture(scope="module")
async def timelock_init(contract_classes):
    account_cls, timelock_cls, target_cls, erc721_cls, mal_target_cls = contract_classes

    # contract deployments
    starknet = await Starknet.empty()
    proposer = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[signer.public_key]
    )
    executor = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[signer.public_key]
    )

    # add accounts to proposers, executors, and cancellers arrays
    PROPOSERS.append(proposer.contract_address)
    EXECUTORS.append(executor.contract_address)
    CANCELLERS.append(proposer.contract_address)

    timelock = await starknet.deploy(
        contract_class=timelock_cls,
        constructor_calldata=[
            MIN_DELAY,                  # delay
            proposer.contract_address,  # deployer
            len(PROPOSERS),             # proposers length
            *PROPOSERS,                 # proposers array
            len(EXECUTORS),             # executors length
            *EXECUTORS,                 # executors array
            len(CANCELLERS),            # cancellers length
            *CANCELLERS                 # cancellers array
        ],
    )
    target = await starknet.deploy(
        contract_class=target_cls
    )
    erc721 = await starknet.deploy(
        contract_class=erc721_cls,
        constructor_calldata=[
            str_to_felt("Non Fungible Token"),  # name
            str_to_felt("NFT"),                 # ticker
            proposer.contract_address           # owner
        ]
    )
    mal_target = await starknet.deploy(
        contract_class=mal_target_cls
    )

    return starknet.state, proposer, executor, timelock, target, erc721, mal_target


@pytest.fixture
async def timelock_factory(contract_classes, timelock_init):
    account_cls, timelock_cls, target_cls, *_ = contract_classes
    state, proposer, executor, timelock, target, *_ = timelock_init

    # cache contracts
    _state = state.copy()
    proposer = cached_contract(_state, account_cls, proposer)
    executor = cached_contract(_state, account_cls, executor)
    timelock = cached_contract(_state, timelock_cls, timelock)
    target = cached_contract(_state, target_cls, target)

    return timelock, proposer, executor, target, _state


@pytest.fixture
async def timelock_with_erc721(timelock_init):
    _, account, _, timelock, _, erc721, _ = timelock_init

    # mint token to account
    await signer.send_transaction(
        account, erc721.contract_address, 'mint', [
            account.contract_address,
            *TOKEN,
        ]
    )

    return timelock, account, erc721


@pytest.fixture
async def timelock_reentrancy(timelock_init):
    state, proposer, _, timelock, _, _, mal_target = timelock_init

    # grant zero address the executor role to test reentrant call
    await signer.send_transaction(
        proposer, timelock.contract_address, 'grantRole', [
            EXECUTOR_ROLE,
            ZERO_ADDRESS,
        ]
    )

    return timelock, proposer, mal_target, state

#
# constructor
#


@pytest.mark.asyncio
@pytest.mark.parametrize('role, addresses, not_role', [
    [PROPOSER_ROLE, PROPOSERS, EXECUTOR_ROLE],
    [CANCELLER_ROLE, CANCELLERS, EXECUTOR_ROLE],
    [EXECUTOR_ROLE, EXECUTORS, PROPOSER_ROLE],
])
async def test_constructor_roles_arrays(timelock_factory, role, addresses, not_role):
    timelock, *_ = timelock_factory

    for i in range(len(addresses)):
        execution_info = await timelock.hasRole(role, addresses[i]).invoke()
        assert execution_info.result == (TRUE,)

        execution_info = await timelock.hasRole(not_role, addresses[i]).invoke()
        assert execution_info.result == (FALSE,)


@pytest.mark.asyncio
async def test_constructor(timelock_factory):
    timelock, deployer, *_ = timelock_factory

    # check delay
    execution_info = await timelock.getMinDelay().invoke()
    assert execution_info.result == (MIN_DELAY,)

    # check self as admin
    execution_info = await timelock.hasRole(TIMELOCK_ADMIN_ROLE, timelock.contract_address).invoke()
    assert execution_info.result == (TRUE,)

    # check deployer as admin
    execution_info = await timelock.hasRole(TIMELOCK_ADMIN_ROLE, deployer.contract_address).invoke()
    assert execution_info.result == (TRUE,)


@pytest.mark.asyncio
@pytest.mark.parametrize('interface_id, result', [
    [IERC165_ID, TRUE],
    [IERC721_RECEIVER_ID, TRUE],
    [IERC1155_RECEIVER_ID, TRUE],
    [IACCESSCONTROL_ID, TRUE],
    [INVALID_ID, FALSE],
    [UNSUPPORTED_ID, FALSE],
])
async def test_registered_interfaces(timelock_factory, interface_id, result):
    timelock, _, *_ = timelock_factory

    execution_info = await timelock.supportsInterface(interface_id).invoke()
    assert execution_info.result == (result,)


#
# hash_operation
#


async def test_hash_operation(timelock_factory):
    timelock, _, _, target, _ = timelock_factory

    # hash single operation
    operation = single_operation(target.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, SALT).invoke()

    calculate_hash_operation = timelock_hash_chain(
        build_call(target.contract_address),
        0,
        SALT
    )

    assert execution_info.result.hash == calculate_hash_operation


@pytest.mark.asyncio
async def test_hash_operation_batch(timelock_factory):
    timelock, _, _, target, _ = timelock_factory

    # hash batched operations
    operation = batched_operations(target.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, SALT).invoke()

    # fetch hash id
    calculate_hash_operation = timelock_hash_chain(
        build_batch(target.contract_address),
        0,
        SALT
    )

    assert execution_info.result.hash == calculate_hash_operation


@pytest.mark.asyncio
async def test_hash_operation_batch_with_predecessor(timelock_factory):
    timelock, _, _, target, _ = timelock_factory

    predecessor = 9999

    # hash batched operations with predecessor
    operation = batched_operations(target.contract_address)
    execution_info = await timelock.hashOperation(*operation, predecessor, SALT).invoke()

    calculate_hash_operation = timelock_hash_chain(
        build_batch(target.contract_address),
        predecessor,
        SALT
    )

    assert execution_info.result.hash == calculate_hash_operation

#
# schedule
#


@pytest.mark.asyncio
async def test_schedule_is_scheduled(timelock_factory):
    timelock, proposer, _, target, _ = timelock_factory

    # get hash id
    operation = single_operation(target.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, SALT).invoke()
    hash_id = execution_info.result.hash

    execution_info = await signer.send_transactions(
        proposer,
        [
            (timelock.contract_address, 'isOperation', [hash_id]),
            (timelock.contract_address, 'isOperationPending', [hash_id]),
            (timelock.contract_address, 'isOperationReady', [hash_id]),
            (timelock.contract_address, 'isOperationDone', [hash_id]),
            (timelock.contract_address, 'getTimestamp', [hash_id]),
        ]
    )

    assert execution_info.result.response == [
        FALSE,      # isOperation
        FALSE,      # isOperationPending
        FALSE,      # isOperationReady
        FALSE,      # isOperationDone
        0           # getTimestamp
    ]

    # format call array and schedule operation
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    tx_exec_info = await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,    # call array
            0,              # predecessor
            SALT,           # SALT
            MIN_DELAY       # delay
        ])

    # check values
    execution_info = await signer.send_transactions(
        proposer,
        [
            (timelock.contract_address, 'isOperation', [hash_id]),
            (timelock.contract_address, 'isOperationPending', [hash_id]),
            (timelock.contract_address, 'isOperationReady', [hash_id]),
            (timelock.contract_address, 'isOperationDone', [hash_id]),
            (timelock.contract_address, 'getTimestamp', [hash_id]),
        ]
    )

    assert execution_info.result.response == [
        TRUE,       # isOperation
        TRUE,       # isOperationPending
        FALSE,      # isOperationReady
        FALSE,      # isOperationDone
        MIN_DELAY   # getTimestamp
    ]

    # check event
    assert_event_emitted(
        tx_exec_info,
        from_address=timelock.contract_address,
        name='CallScheduled',
        data=[
            hash_id,                                     # id
            0,                                           # index
            target.contract_address,                     # target
            get_selector_from_name("increase_balance"),  # selector
            1,                                           # calldata length
            AMOUNT,                                      # calldata
            0,                                           # predecessor
            MIN_DELAY                                    # delay
        ]
    )


@pytest.mark.asyncio
async def test_schedule_prevents_overwriting_active_operation(timelock_factory):
    timelock, proposer, _, target, _ = timelock_factory

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    # repeated operation should fail
    await assert_revert(signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ]),
        reverted_with="Timelock: operation already scheduled"
    )


@pytest.mark.asyncio
async def test_schedule_prevents_nonproposer_from_committing(timelock_factory):
    timelock, _, nonproposer, target, _ = timelock_factory

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # non-proposer invocation should fail
    await assert_revert(signer.send_transaction(
        nonproposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ]),
        f"AccessControl: caller is missing role {role_repr(PROPOSER_ROLE)}"
    )


@pytest.mark.asyncio
async def test_schedule_enforce_minimum_delay(timelock_factory):
    timelock, proposer, _, target, _ = timelock_factory

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # delay under threshold should fail
    await assert_revert(signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            BAD_DELAY                                # delay
        ]),
        reverted_with="Timelock: insufficient delay"
    )

#
# execute
#


@pytest.mark.asyncio
async def test_execute_when_operation_not_scheduled(timelock_factory):
    timelock, _, executor, target, _ = timelock_factory

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # execute should fail when not ready
    await assert_revert(signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
        ]),
        reverted_with="Timelock: operation is not ready"
    )


@pytest.mark.asyncio
async def test_execute_when_too_early(timelock_factory):
    timelock, proposer, executor, target, state = timelock_factory

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    set_block_timestamp(state, MIN_DELAY - 1)

    # operation should fail when under delay
    await assert_revert(signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
        ]),
        reverted_with="Timelock: operation is not ready"
    )


@pytest.mark.asyncio
async def test_execute(timelock_factory):
    timelock, proposer, executor, target, state = timelock_factory

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    # get hash id
    operation = single_operation(target.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, SALT).invoke()
    hash_id = execution_info.result.hash

    execution_info = await signer.send_transactions(
        proposer,
        [
            (timelock.contract_address, 'isOperationPending', [hash_id]),
            (timelock.contract_address, 'isOperationDone', [hash_id]),
        ]
    )

    assert execution_info.result.response == [
        TRUE,       # isOperationPending
        FALSE       # isOperationDone
    ]

    set_block_timestamp(state, FF_PAST_DELAY)

    # execute
    tx_exec_info = await signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,    # call array
            0,              # predecessor
            SALT,           # SALT
        ])

    # check values
    execution_info = await signer.send_transactions(
        proposer,
        [
            (timelock.contract_address, 'isOperationPending', [hash_id]),
            (timelock.contract_address, 'isOperationDone', [hash_id]),
        ]
    )

    assert execution_info.result.response == [
        FALSE,       # isOperationPending
        TRUE         # isOperationDone
    ]

    # check event
    assert_event_emitted(
        tx_exec_info,
        from_address=timelock.contract_address,
        name='CallExecuted',
        data=[
            hash_id,                                     # id
            0,                                           # index
            target.contract_address,                     # target
            get_selector_from_name("increase_balance"),  # selector
            1,                                           # calldata length
            AMOUNT,                                      # calldata
        ]
    )


@pytest.mark.asyncio
async def test_execute_prevent_nonexecutor_from_reveal(timelock_factory):
    timelock, proposer, _, target, state = timelock_factory

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    set_block_timestamp(state, FF_PAST_DELAY)

    # execute with non-executor
    await assert_revert(signer.send_transaction(
        proposer, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
        ]),
        f"AccessControl: caller is missing role {role_repr(EXECUTOR_ROLE)}"
    )

#
# batch schedule
#


@pytest.mark.asyncio
async def test_schedule_batch_is_scheduled(timelock_factory):
    timelock, proposer, _, target, state = timelock_factory

    # get hash id
    operation = batched_operations(target.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, SALT).invoke()
    hash_id = execution_info.result.hash

    execution_info = await signer.send_transactions(
        proposer,
        [
            (timelock.contract_address, 'isOperation', [hash_id]),
            (timelock.contract_address, 'isOperationPending', [hash_id]),
            (timelock.contract_address, 'isOperationReady', [hash_id]),
            (timelock.contract_address, 'isOperationDone', [hash_id]),
            (timelock.contract_address, 'getTimestamp', [hash_id]),
        ]
    )

    assert execution_info.result.response == [
        FALSE,      # isOperation
        FALSE,      # isOperationPending
        FALSE,      # isOperationReady
        FALSE,      # isOperationDone
        0           # getTimestamp
    ]

    # format call array
    call_array = flatten_calls(
        batched_operations(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    # check values
    execution_info = await signer.send_transactions(
        proposer,
        [
            (timelock.contract_address, 'isOperation', [hash_id]),
            (timelock.contract_address, 'isOperationPending', [hash_id]),
            (timelock.contract_address, 'isOperationReady', [hash_id]),
            (timelock.contract_address, 'isOperationDone', [hash_id]),
            (timelock.contract_address, 'getTimestamp', [hash_id]),
        ]
    )

    assert execution_info.result.response == [
        TRUE,       # isOperation
        TRUE,       # isOperationPending
        FALSE,      # isOperationReady
        FALSE,      # isOperationDone
        MIN_DELAY   # getTimestamp
    ]

@pytest.mark.asyncio
async def test_schedule_batch_emits_events(timelock_factory):
    timelock, proposer, _, target, _ = timelock_factory

    # get hash id
    operation = batched_operations(target.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, SALT).invoke()
    hash_id = execution_info.result.hash

    # format call array
    call_array = flatten_calls(
        batched_operations(target.contract_address)
    )

    # schedule operations
    tx_exec_info = await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    # check events
    num_calls = call_array[0]

    for index in range(0, num_calls):
        assert_event_emitted(
            tx_exec_info,
            from_address=timelock.contract_address,
            name='CallScheduled',
            data=[
                hash_id,                                     # id
                index,                                       # index
                target.contract_address,                     # target
                get_selector_from_name("increase_balance"),  # selector
                1,                                           # calldata length
                AMOUNT,                                      # calldata
                0,                                           # predecessor
                MIN_DELAY                                    # delay
            ]
        )


@pytest.mark.asyncio
async def test_schedule_batch_prevents_overwriting_active_operation(timelock_factory):
    timelock, proposer, _, target, _ = timelock_factory

    # format call array
    call_array = flatten_calls(
        batched_operations(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    # repeated operation should fail
    await assert_revert(signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ]),
        reverted_with="Timelock: operation already scheduled"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('bad_params', [
    ["add"],
    ["sub"]
])
async def test_schedule_batch_mismatched_calldata_params(timelock_factory, bad_params):
    timelock, proposer, _, target, _ = timelock_factory

    # format array
    call_array = flatten_calls(
        batched_operations(target.contract_address)
    )

    # add/remove last calldata element
    def bad_calldata_len(param):
        if param == "add":
            x = call_array[-1]
            call_array.append(x)
        else:
            call_array.pop()
        return call_array

    # wrong calldata length should revert
    await assert_revert(signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *bad_calldata_len(bad_params),           # bad call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('bad_params', [
    ["add"],
    ["sub"]
])
async def test_schedule_batch_mismatched_address_params(timelock_factory, bad_params):
    timelock, proposer, _, target, _ = timelock_factory

    # format bad array
    call_array = flatten_calls(
        batched_operations(target.contract_address)
    )

    # increase/decrease address length
    def bad_address_len(param):
        x = call_array.copy()
        if param == "add":
            x[0] = call_array[0] + 1
        else:
            x[0] = call_array[0] - 1
        return x

    # wrong address length should revert
    await assert_revert(signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *bad_address_len(bad_params),            # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])
    )


@pytest.mark.asyncio
async def test_schedule_batch_prevents_nonproposer_from_committing(timelock_factory):
    timelock, _, nonproposer, target, _ = timelock_factory

    # format call array
    call_array = flatten_calls(
        batched_operations(target.contract_address)
    )

    # non-proposer invocation should fail
    await assert_revert(signer.send_transaction(
        nonproposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ]),
        f"AccessControl: caller is missing role {role_repr(PROPOSER_ROLE)}"
    )


@pytest.mark.asyncio
async def test_schedule_batch_enforce_minimum_delay(timelock_factory):
    timelock, proposer, _, target, _ = timelock_factory

    # format call array
    call_array = flatten_calls(
        batched_operations(target.contract_address)
    )

    # delay under threshold should fail
    await assert_revert(signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            BAD_DELAY                                # delay
        ]),
        reverted_with="Timelock: insufficient delay"
    )

#
# execute batch
#


@pytest.mark.asyncio
async def test_execute_batch(timelock_factory):
    timelock, proposer, executor, target, state = timelock_factory

    # format call array
    call_array = flatten_calls(
        batched_operations(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    # get hash id
    operation = batched_operations(target.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, SALT).invoke()
    hash_id = execution_info.result.hash

    execution_info = await signer.send_transactions(
        proposer,
        [
            (timelock.contract_address, 'isOperationPending', [hash_id]),
            (timelock.contract_address, 'isOperationDone', [hash_id]),
        ]
    )

    assert execution_info.result.response == [
        TRUE,       # isOperationPending
        FALSE       # isOperationDone
    ]

    set_block_timestamp(state, FF_PAST_DELAY)

    # execute
    tx_exec_info = await signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
        ])

    # check values
    execution_info = await signer.send_transactions(
        proposer,
        [
            (timelock.contract_address, 'isOperationPending', [hash_id]),
            (timelock.contract_address, 'isOperationDone', [hash_id]),
        ]
    )

    assert execution_info.result.response == [
        FALSE,       # isOperationPending
        TRUE         # isOperationDone
    ]

    # check events
    for index in range(0, call_array[0]):
        assert_event_emitted(
            tx_exec_info,
            from_address=timelock.contract_address,
            name='CallExecuted',
            data=[
                hash_id,                                     # id
                index,                                       # index
                target.contract_address,                     # target
                get_selector_from_name("increase_balance"),  # selector
                1,                                           # calldata length
                AMOUNT,                                      # calldata
            ]
        )


@pytest.mark.asyncio
async def test_execute_batch_when_operation_not_scheduled(timelock_factory):
    timelock, _, executor, target, _ = timelock_factory

    # format call array
    call_array = flatten_calls(
        batched_operations(target.contract_address)
    )

    # execute should fail when not scheduled
    await assert_revert(signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
        ]),
        reverted_with="Timelock: operation is not ready"
    )


@pytest.mark.asyncio
async def test_execute_batch_when_too_early_PART_ONE(timelock_factory):
    timelock, proposer, executor, target, _ = timelock_factory

    # format call array
    call_array = flatten_calls(
        batched_operations(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    # operation should fail when under delay
    await assert_revert(signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
        ]),
        reverted_with="Timelock: operation is not ready"
    )


@pytest.mark.asyncio
async def test_execute_batch_when_too_early_PART_TWO(timelock_factory):
    timelock, proposer, executor, target, state = timelock_factory

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    set_block_timestamp(state, MIN_DELAY - 1)

    # operation should fail when under delay
    await assert_revert(signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
        ]),
        reverted_with="Timelock: operation is not ready"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('bad_params', [
    ["add"],
    ["sub"]
])
async def test_execute_batch_mismatched_calldata_params(timelock_factory, bad_params):
    timelock, proposer, executor, target, state = timelock_factory

    # format call array
    call_array = flatten_calls(
        batched_operations(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    set_block_timestamp(state, FF_PAST_DELAY)

    def bad_calldata_len(param):
        if param == "add":
            x = call_array[-1]
            call_array.append(x)
        else:
            call_array.pop()
        return call_array

    # wrong calldata length should revert
    await assert_revert(signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *bad_calldata_len(bad_params),           # call array
            0,                                       # predecessor
            SALT                                     # SALT
        ])
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('bad_params', [
    ["add"],
    ["sub"]
])
async def test_execute_batch_mismatched_address_params(timelock_factory, bad_params):
    timelock, proposer, executor, target, state = timelock_factory

    # format call array
    call_array = flatten_calls(
        batched_operations(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    set_block_timestamp(state, FF_PAST_DELAY)

    def bad_address_len(param):
        x = call_array.copy()
        if param == "add":
            x[0] = call_array[0] + 1
        else:
            x[0] = call_array[0] - 1
        return x

    # wrong address len should revert
    await assert_revert(signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *bad_address_len(bad_params),            # call array
            0,                                       # predecessor
            SALT                                     # SALT
        ])
    )


@pytest.mark.asyncio
async def test_execute_batch_partial_execution(timelock_factory):
    timelock, proposer, executor, target, state = timelock_factory

    def bad_batch(address):
        return from_call_to_call_array([
            *build_call(address),               # call
            [address, "increase_balance", []],  # bad call
            *build_call(address)                # call
        ])

    # format call array
    bad_array = flatten_calls(
        bad_batch(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *bad_array,                              # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    set_block_timestamp(state, FF_PAST_DELAY)

    # execute
    await assert_revert(signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *bad_array,                              # call array
            0,                                       # predecessor
            SALT,                                    # SALT
        ]),
        reverted_with="Timelock: underlying transaction reverted"
    )

#
# cancel
#


@pytest.mark.asyncio
async def test_canceller_can_cancel(timelock_factory):
    timelock, proposer, _, target, _ = timelock_factory

    # get hash id
    operation = single_operation(target.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, SALT).invoke()
    hash_id = execution_info.result.hash

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    # cancel (proposer also has canceller role)
    tx_exec_info = await signer.send_transaction(
        proposer, timelock.contract_address, "cancel", [hash_id]
    )

    execution_info = await signer.send_transactions(
        proposer,
        [
            (timelock.contract_address, 'isOperation', [hash_id]),
            (timelock.contract_address, 'isOperationPending', [hash_id]),
            (timelock.contract_address, 'isOperationReady', [hash_id]),
            (timelock.contract_address, 'isOperationDone', [hash_id]),
            (timelock.contract_address, 'getTimestamp', [hash_id])
        ]
    )

    assert execution_info.result.response == [
        FALSE,      # isOperation
        FALSE,      # isOperationPending
        FALSE,      # isOperationReady
        FALSE,      # isOperationDone
        0           # getTimestamp
    ]

    # check event
    assert_event_emitted(
        tx_exec_info,
        from_address=timelock.contract_address,
        name='Cancelled',
        data=[hash_id]
    )


@pytest.mark.asyncio
async def test_cancel_invalid_operation(timelock_factory):
    timelock, proposer, _, _, _ = timelock_factory

    # cancel (proposer also has canceller role)
    await assert_revert(signer.send_transaction(
        proposer, timelock.contract_address, "cancel", [INVALID_ID]),
        reverted_with="Timelock: operation cannot be cancelled"
    )


@pytest.mark.asyncio
async def test_cancel_from_noncanceller(timelock_factory):
    timelock, proposer, noncanceller, target, _ = timelock_factory

    # get hash id
    operation = single_operation(target.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, SALT).invoke()
    hash_id = execution_info.result.hash

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    # cancel (proposer also has canceller role)
    await assert_revert(signer.send_transaction(
        noncanceller, timelock.contract_address, "cancel", [hash_id]),
        f"AccessControl: caller is missing role {role_repr(CANCELLER_ROLE)}"
    )

#
# update_delay
#


@pytest.mark.asyncio
async def test_update_delay_from_unauthorized(timelock_factory):
    timelock, other, _, _, _ = timelock_factory

    # should fail since timelock contract must be the caller
    await assert_revert(signer.send_transaction(
        other, timelock.contract_address, "updateDelay", [NEW_MIN_DELAY]),
        reverted_with="Timelock: caller must be timelock"
    )


@pytest.mark.asyncio
async def test_update_delay_scheduled_maintenance(timelock_factory):
    timelock, proposer, executor, _, state = timelock_factory

    update_delay_call = from_call_to_call_array(
        [[timelock.contract_address, "updateDelay", [NEW_MIN_DELAY]]]
    )

    # format call array
    call_array = flatten_calls(update_delay_call)

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    set_block_timestamp(state, FF_PAST_DELAY)

    # execute
    tx_exec_info = await signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
        ])

    # check event
    assert_event_emitted(
        tx_exec_info,
        from_address=timelock.contract_address,
        name='MinDelayChange',
        data=[
            MIN_DELAY,
            NEW_MIN_DELAY,
        ]
    )

   # check new delay is set
    execution_info = await timelock.getMinDelay().invoke()
    assert execution_info.result == (NEW_MIN_DELAY,)

#
# dependency
#


@pytest.mark.asyncio
async def test_execute_before_dependency(timelock_factory):
    timelock, proposer, executor, target, state = timelock_factory

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # get hash id
    operation = single_operation(target.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, SALT).invoke()
    hash_id_1 = execution_info.result.hash

    # schedule operations
    await signer.send_transactions(
        proposer,
        [
            (timelock.contract_address, 'schedule', [*call_array, 0, SALT, MIN_DELAY]),
            (timelock.contract_address, 'schedule', [*call_array, hash_id_1, SALT, MIN_DELAY]),
        ]
    )

    set_block_timestamp(state, FF_PAST_DELAY)

    # execute
    await assert_revert(signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            hash_id_1,                               # predecessor
            SALT,                                    # SALT
        ]),
        reverted_with="Timelock: missing dependency"
    )


@pytest.mark.asyncio
async def test_execute_after_dependency(timelock_factory):
    timelock, proposer, executor, target, state = timelock_factory

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # get hash id
    operation = single_operation(target.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, SALT).invoke()
    hash_id_1 = execution_info.result.hash

    # schedule operations
    await signer.send_transactions(
        proposer,
        [
            (timelock.contract_address, 'schedule',
                [*call_array, 0, SALT, MIN_DELAY]
            ),
            (timelock.contract_address, 'schedule',
                [*call_array, hash_id_1, SALT, MIN_DELAY]
            ),
        ]
    )

    set_block_timestamp(state, FF_PAST_DELAY)

    # execute 1
    await signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                               # call array
            0,                                         # predecessor
            SALT,                                      # SALT
        ])

    # execute 2
    await signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                               # call array
            hash_id_1,                                 # predecessor
            SALT,                                      # SALT
        ])

#
# usage scenario
#


@pytest.mark.asyncio
async def test_execute_check_target_contract(timelock_factory):
    timelock, proposer, executor, target, state = timelock_factory

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
            MIN_DELAY                                # delay
        ])

    set_block_timestamp(state, FF_PAST_DELAY)

    # execute
    await signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            SALT,                                    # SALT
        ])

    execution_info = await target.get_balance().invoke()
    assert execution_info.result.res == AMOUNT


@pytest.mark.asyncio
async def test_execute_reentrancy(timelock_reentrancy):
    timelock, proposer, mal_target, state = timelock_reentrancy

    # format call array and schedule malicious operation
    call_array = flatten_calls(
        single_operation(mal_target.contract_address)
    )

    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,    # call array
            0,              # predecessor
            SALT,           # SALT
            MIN_DELAY       # delay
        ])

    set_block_timestamp(state, FF_PAST_DELAY)

    # execute malicious operation
    mal_operation = single_operation(mal_target.contract_address)
    await assert_revert(
        timelock.execute(*mal_operation, 0, SALT).invoke(),
        reverted_with="Timelock: operation is not ready"
    )

    execution_info = await mal_target.get_balance().invoke()
    assert execution_info.result.res == 0

#
# safe receive
#


@pytest.mark.asyncio
async def test_receive_erc721_safe_transfer(timelock_with_erc721):
    timelock, owner, erc721 = timelock_with_erc721

    await signer.send_transaction(
        owner, erc721.contract_address, 'safeTransferFrom', [
            owner.contract_address,
            timelock.contract_address,
            *TOKEN,
            len(DATA),
            *DATA
        ]
    )

#
# timestamp overflow
#


@pytest.mark.asyncio
async def test_schedule_enforce_overflow_check(timelock_factory):
    timelock, proposer, _, target, state = timelock_factory

    # format call array
    call_array = flatten_calls(
        single_operation(target.contract_address)
    )

    # set timestamp otherwise felt can't hold overflowing int
    set_block_timestamp(state, 2**128)
    delay_overflow = 2**128

    # delay overflow should fail
    await assert_revert(signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,    # call array
            0,              # predecessor
            SALT,           # SALT
            delay_overflow  # delay
        ]),
        reverted_with="Timelock: timestamp overflow"
    )
