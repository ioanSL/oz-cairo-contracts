import pytest
from itertools import count
from starkware.starknet.testing.starknet import Starknet
from starkware.starknet.public.abi import get_selector_from_name
from starkware.starkware_utils.error_handling import StarkException
from starkware.starknet.definitions.error_codes import StarknetErrorCode
from starkware.starknet.compiler.compile import compile_starknet_files
from starkware.cairo.common.hash_state import compute_hash_on_elements


from utils import (
    TestSigner, assert_event_emitted, assert_revert, get_contract_def,
    cached_contract, get_block_timestamp, TRUE, FALSE, set_block_timestamp,
    format_calls_for_calls, format_calls_for_signer
)

signer = TestSigner(123456789987654321)

TIMELOCK_ADMIN_ROLE = 0x11
PROPOSER_ROLE = 0x22
CANCELLER_ROLE = 0x33
EXECUTOR_ROLE = 0x44

PROPOSERS = [111, 112, 113, 114]
EXECUTORS = [221, 222, 223, 224]

MIN_DELAY = 86400
BAD_DELAY = 100
HELPER_CALLDATA = 5
PREDECESSOR = get_selector_from_name("decreaseCount")

# random amount for helper contract
INIT_COUNT = 100

# to prevent hash id collisions between tests, the salt is incremented for test case
SALT_IID = count(100)


def gen_operation(address):
    return format_calls_for_calls(
        [
            [address, "increaseCount", [HELPER_CALLDATA]]
        ]
    )


def batch_operations(address):
    return format_calls_for_calls(
        [
            [address, "increaseCount", [HELPER_CALLDATA]],
            [address, "increaseCount", [HELPER_CALLDATA]],
            [address, "increaseCount", [HELPER_CALLDATA]]
        ]
    )


@pytest.fixture(scope="module")
async def contract_defs():
    account_def = get_contract_def("openzeppelin/account/Account.cairo")
    timelock_def = get_contract_def("openzeppelin/governance/timelock/Timelock.cairo")
    helper_def = get_contract_def("tests/mocks/TimelockHelper.cairo")

    return account_def, timelock_def, helper_def


@pytest.fixture(scope="module")
async def timelock_init(contract_defs):
    account_def, timelock_def, helper_def = contract_defs
    starknet = await Starknet.empty()

    proposer = await starknet.deploy(
        contract_def=account_def,
        constructor_calldata=[signer.public_key]
    )
    executor = await starknet.deploy(
        contract_def=account_def,
        constructor_calldata=[signer.public_key]
    )

    # add accounts to proposers and executors arrays
    PROPOSERS.append(proposer.contract_address)
    EXECUTORS.append(executor.contract_address)

    timelock = await starknet.deploy(
        contract_def=timelock_def,
        constructor_calldata=[
            MIN_DELAY,                  # delay
            proposer.contract_address,  # deployer
            len(PROPOSERS),             # proposers length
            *PROPOSERS,                 # proposers array
            len(EXECUTORS),             # executors length
            *EXECUTORS                  # executors array
        ],
    )
    helper = await starknet.deploy(
        contract_def=helper_def,
        constructor_calldata=[INIT_COUNT]
    )

    return starknet.state, proposer, executor, timelock, helper


@pytest.fixture(scope="module")
async def timelock_factory(contract_defs, timelock_init):
    account_def, timelock_def, helper_def = contract_defs
    state, proposer, executor, timelock, helper = timelock_init
    _state = state.copy()
    proposer = cached_contract(_state, account_def, proposer)
    executor = cached_contract(_state, account_def, executor)
    timelock = cached_contract(_state, timelock_def, timelock)
    helper = cached_contract(_state, helper_def, helper)


    return timelock, proposer, executor, helper, state

#
# constructor
#

@pytest.mark.asyncio
@pytest.mark.parametrize('role, addresses, not_role', [
    [PROPOSER_ROLE, PROPOSERS, EXECUTOR_ROLE],
    [CANCELLER_ROLE, PROPOSERS, EXECUTOR_ROLE],
    [EXECUTOR_ROLE, EXECUTORS, PROPOSER_ROLE],
])
async def test_constructor_roles_arrays(timelock_factory, role, addresses, not_role):
    timelock, *_ = timelock_factory

    for i in range(len(addresses)):
        execution_info = await timelock.hasRole(role, addresses[i]).call()
        assert execution_info.result == (TRUE,)

        execution_info = await timelock.hasRole(not_role, addresses[i]).call()
        assert execution_info.result == (FALSE,)


@pytest.mark.asyncio
async def test_constructor(timelock_factory):
    timelock, deployer, *_ = timelock_factory

    # check delay
    execution_info = await timelock.getMinDelay().call()
    assert execution_info.result == (MIN_DELAY,)

    # check self as admin
    execution_info = await timelock.hasRole(TIMELOCK_ADMIN_ROLE, timelock.contract_address).call()
    assert execution_info.result == (TRUE,)

    # check deployer as admin
    execution_info = await timelock.hasRole(TIMELOCK_ADMIN_ROLE, deployer.contract_address).call()
    assert execution_info.result == (TRUE,)


#
# hashOperation
#

@pytest.mark.asyncio
async def test_hashOperation(timelock_factory):
    timelock, _, _, helper, _ = timelock_factory

    salt = next(SALT_IID)

    # hash single operation
    operation = gen_operation(helper.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, salt).call()

    calculate_hash_operation = compute_hash_on_elements([
        compute_hash_on_elements([
            helper.contract_address,                        # to
            get_selector_from_name("increaseCount"),        # selector
            compute_hash_on_elements([HELPER_CALLDATA])]),  # hashed calldata
        1,                                                  # calldata length
        0,                                                  # predecessor
        salt                                                # salt
    ])

    assert execution_info.result.hash == calculate_hash_operation


@pytest.mark.asyncio
async def test_hashOperation_batch(timelock_factory):
    timelock, _, _, helper, _ = timelock_factory

    salt = next(SALT_IID)

    # hash batched operations
    operation = batch_operations(helper.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, salt).call()

    call = compute_hash_on_elements([
        helper.contract_address,
        get_selector_from_name("increaseCount"),
        compute_hash_on_elements([HELPER_CALLDATA])
    ])

    calculate_hash_operation = compute_hash_on_elements([
        call,                                               #
        call,                                               # calls
        call,                                               #
        3,                                                  # calldata length
        0,                                                  # predecessor
        salt                                                # salt
    ])
            

    assert execution_info.result.hash == calculate_hash_operation


@pytest.mark.asyncio
async def test_hashOperation_batch_with_predecessor(timelock_factory):
    timelock, _, _, helper, _ = timelock_factory

    salt = next(SALT_IID)

    # hash batched operations with predecessor
    operation = batch_operations(helper.contract_address)
    execution_info = await timelock.hashOperation(*operation, PREDECESSOR, salt).call()

    call = compute_hash_on_elements([
        helper.contract_address,
        get_selector_from_name("increaseCount"),
        compute_hash_on_elements([HELPER_CALLDATA])
    ])

    calculate_hash_operation = compute_hash_on_elements([
        call,                                               #
        call,                                               # calls
        call,                                               #
        3,                                                  # calldata length
        PREDECESSOR,                                        # predecessor
        salt                                                # salt
    ])

    assert execution_info.result.hash == calculate_hash_operation

#
# schedule
#

@pytest.mark.asyncio
async def test_schedule_is_scheduled(timelock_factory):
    timelock, proposer, _, helper, _ = timelock_factory

    salt = next(SALT_IID)

    # get hash id
    operation = gen_operation(helper.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, salt).call()
    hash_id = execution_info.result.hash

    # check id is not scheduled
    execution_info = await timelock.isOperation(hash_id).call()
    assert execution_info.result == (FALSE,)

    # check id is not pending
    execution_info = await timelock.isOperationPending(hash_id).call()
    assert execution_info.result == (FALSE,)

    # check id is not ready
    execution_info = await timelock.isOperationReady(hash_id).call()
    assert execution_info.result == (FALSE,)

    # check id is not done
    execution_info = await timelock.isOperationDone(hash_id).call()
    assert execution_info.result == (FALSE,)

    # check timestamp
    execution_info = await timelock.getTimestamp(hash_id).call()
    assert execution_info.result == (0,)

    # format call array
    call_array = format_calls_for_signer(
        gen_operation(helper.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
            MIN_DELAY                                # delay
        ])

    # check id is scheduled
    execution_info = await timelock.isOperation(hash_id).call()
    assert execution_info.result == (TRUE,)

    # check id is pending
    execution_info = await timelock.isOperationPending(hash_id).call()
    assert execution_info.result == (TRUE,)

    # check id is not ready
    execution_info = await timelock.isOperationReady(hash_id).call()
    assert execution_info.result == (FALSE,)

    # check id is not done
    execution_info = await timelock.isOperationDone(hash_id).call()
    assert execution_info.result == (FALSE,)

    # check timestamp
    execution_info = await timelock.getTimestamp(hash_id).call()
    assert execution_info.result == (MIN_DELAY,)


@pytest.mark.asyncio
async def test_schedule_emits_event(timelock_factory):
    timelock, proposer, _, helper, _ = timelock_factory

    salt = next(SALT_IID)

    # get hash id
    operation = gen_operation(helper.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, salt).call()
    hash_id = execution_info.result.hash

    # format call array
    call_array = format_calls_for_signer(
        gen_operation(helper.contract_address)
    )

    # schedule operation
    tx_exec_info = await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
            MIN_DELAY                                # delay
        ])

    # check event
    assert_event_emitted(
        tx_exec_info,
        from_address=timelock.contract_address,
        name='CallScheduled',
        data=[
            hash_id,                                 # id
            0,                                       # index
            helper.contract_address,                 # target
            get_selector_from_name("increaseCount"), # selector
            1,                                       # calldata length
            HELPER_CALLDATA,                         # calldata
            0,                                       # predecessor
            MIN_DELAY                                # delay
        ]
    )


@pytest.mark.asyncio
async def test_schedule_prevents_overwriting_active_operation(timelock_factory):
    timelock, proposer, _, helper, _ = timelock_factory

    salt = next(SALT_IID)

    # format call array
    call_array = format_calls_for_signer(
        gen_operation(helper.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
            MIN_DELAY                                # delay
        ])
    
    # repeated operation should fail
    await assert_revert(signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
            MIN_DELAY                                # delay
        ]),
        reverted_with="Timelock: operation already scheduled"
    )

@pytest.mark.asyncio
async def test_schedule_prevents_nonproposer_from_committing(timelock_factory):
    timelock, _, executor, helper, _ = timelock_factory

    salt = next(SALT_IID)

    # format call array
    call_array = format_calls_for_signer(
        gen_operation(helper.contract_address)
    )

    # non-proposer invocation should fail
    await assert_revert(signer.send_transaction(
        executor, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
            MIN_DELAY                                # delay
        ]),
        reverted_with=f"AccessControl: caller is missing role {PROPOSER_ROLE}"
    )


@pytest.mark.asyncio
async def test_schedule_enforce_minimum_delay(timelock_factory):
    timelock, proposer, _, helper, _ = timelock_factory

    salt = next(SALT_IID)

    # format call array
    call_array = format_calls_for_signer(
        gen_operation(helper.contract_address)
    )

    # delay under threshold should fail
    await assert_revert(signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
            BAD_DELAY                                # delay
        ]),
        reverted_with="Timelock: insufficient delay"
    )


@pytest.mark.asyncio
async def test_schedule_enforce_overflow_check(timelock_factory):
    timelock, proposer, _, helper, state = timelock_factory

    salt = next(SALT_IID)

    # format call array
    call_array = format_calls_for_signer(
        gen_operation(helper.contract_address)
    )

    # set timestamp otherwise felt can't hold overflowing int
    set_block_timestamp(state, 2**128)

    delay_overflow = 2**128

    # delay overflow should fail
    await assert_revert(signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
            delay_overflow                           # delay
        ]),
        reverted_with="Timelock: timestamp overflow"
    )

#
# execute
#

@pytest.mark.asyncio
async def test_execute_when_operation_not_scheduled(timelock_factory):
    timelock, proposer, executor, helper, _ = timelock_factory

    salt = next(SALT_IID)

    # format call array
    call_array = format_calls_for_signer(
        gen_operation(helper.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
            MIN_DELAY                                # delay
        ])

    # delay overflow should fail
    await assert_revert(signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
        ]),
        reverted_with="Timelock: operation is not ready"
    )


@pytest.mark.asyncio
async def test_execute_when_too_early_PART_ONE(timelock_factory):
    timelock, proposer, executor, helper, _ = timelock_factory

    salt = next(SALT_IID)

    # format call array
    call_array = format_calls_for_signer(
        gen_operation(helper.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
            MIN_DELAY                                # delay
        ])

    # operation should fail when under delay
    await assert_revert(signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
        ]),
        reverted_with="Timelock: operation is not ready"
    )


@pytest.mark.asyncio
async def test_execute_when_too_early_PART_TWO(timelock_factory):
    timelock, proposer, executor, helper, state = timelock_factory

    salt = next(SALT_IID)

    # format call array
    call_array = format_calls_for_signer(
        gen_operation(helper.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
            MIN_DELAY                                # delay
        ])

    set_block_timestamp(state, MIN_DELAY - 10)

    # operation should fail when under delay
    await assert_revert(signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
        ]),
        reverted_with="Timelock: operation is not ready"
    )


@pytest.mark.asyncio
async def test_execute(timelock_factory):
    timelock, proposer, executor, helper, state = timelock_factory

    salt = next(SALT_IID)

    # format call array
    call_array = format_calls_for_signer(
        gen_operation(helper.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
            MIN_DELAY                                # delay
        ])

    # get hash id
    operation = gen_operation(helper.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, salt).call()
    hash_id = execution_info.result.hash

    # check id is pending
    execution_info = await timelock.isOperationPending(hash_id).call()
    assert execution_info.result == (TRUE,)

    # check id is not done
    execution_info = await timelock.isOperationDone(hash_id).call()
    assert execution_info.result == (FALSE,)

    set_block_timestamp(state, MIN_DELAY+10)

    # execute
    await signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
        ])

    # check id is no longer pending
    execution_info = await timelock.isOperationPending(hash_id).call()
    assert execution_info.result == (FALSE,)

    # check id is done
    execution_info = await timelock.isOperationDone(hash_id).call()
    assert execution_info.result == (TRUE,)


@pytest.mark.asyncio
async def test_execute_emits_event(timelock_factory):
    timelock, proposer, executor, helper, state = timelock_factory

    salt = next(SALT_IID)

    # format call array
    call_array = format_calls_for_signer(
        gen_operation(helper.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
            MIN_DELAY                                # delay
        ])

    # get hash id
    operation = gen_operation(helper.contract_address)
    execution_info = await timelock.hashOperation(*operation, 0, salt).call()
    hash_id = execution_info.result.hash

    set_block_timestamp(state, MIN_DELAY+10)

    # execute
    tx_exec_info = await signer.send_transaction(
        executor, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
        ])

    # check event
    assert_event_emitted(
        tx_exec_info,
        from_address=timelock.contract_address,
        name='CallExecuted',
        data=[
            hash_id,                                 # id
            0,                                       # index
            helper.contract_address,                 # target
            get_selector_from_name("increaseCount"), # selector
            1,                                       # calldata length
            HELPER_CALLDATA,                         # calldata
        ]
    )


@pytest.mark.asyncio
async def test_execute_prevent_nonexecutor_from_reveal(timelock_factory):
    timelock, proposer, _, helper, state = timelock_factory

    salt = next(SALT_IID)

    set_block_timestamp(state, MIN_DELAY)

    # format call array
    call_array = format_calls_for_signer(
        gen_operation(helper.contract_address)
    )

    # schedule operation
    await signer.send_transaction(
        proposer, timelock.contract_address, "schedule", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
            MIN_DELAY                                # delay
        ])

    # execute with non-executor
    await assert_revert(signer.send_transaction(
        proposer, timelock.contract_address, "execute", [
            *call_array,                             # call array
            0,                                       # predecessor
            salt,                                    # salt
        ]),
        reverted_with=f"AccessControl: caller is missing role {EXECUTOR_ROLE}"
    )

