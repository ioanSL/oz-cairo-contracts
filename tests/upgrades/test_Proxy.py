import pytest
from starkware.starkware_utils.error_handling import StarkException
from starkware.starknet.public.abi import get_selector_from_name
from starkware.starknet.testing.starknet import Starknet
from utils import (
    TestSigner,
    assert_revert,
    get_contract_class,
    cached_contract,
    assert_event_emitted,
    ZERO_ADDRESS
)

# random value
VALUE = 123

signer = TestSigner(123456789987654321)


@pytest.fixture(scope='module')
def contract_classes():
    account_cls = get_contract_class('openzeppelin/account/Account.cairo')
    implementation_cls = get_contract_class(
        'tests/mocks/proxiable_implementation.cairo'
    )
    proxy_cls = get_contract_class('openzeppelin/upgrades/Proxy.cairo')

    return account_cls, implementation_cls, proxy_cls


@pytest.fixture(scope='module')
async def proxy_init(contract_classes):
    account_cls, implementation_cls, proxy_cls = contract_classes
    starknet = await Starknet.empty()
    account = await starknet.deploy(
        contract_class=account_cls,
        constructor_calldata=[signer.public_key]
    )
    implementation_decl = await starknet.declare(
        contract_class=implementation_cls
    )
    proxy = await starknet.deploy(
        contract_class=proxy_cls,
        constructor_calldata=[implementation_decl.class_hash]
    )
    return (
        starknet.state,
        account,
        proxy
    )


@pytest.fixture
def proxy_factory(contract_classes, proxy_init):
    account_cls, _, proxy_cls = contract_classes
    state, account, proxy = proxy_init
    _state = state.copy()
    account = cached_contract(_state, account_cls, account)
    proxy = cached_contract(_state, proxy_cls, proxy)

    return account, proxy


@pytest.fixture
async def after_initialized(proxy_factory):
    account, proxy = proxy_factory
    
    # initialize proxy
    await signer.send_transaction(
        account, proxy.contract_address, 'initializer', [account.contract_address]
    )

    return account, proxy

#
# constructor
#

@pytest.mark.asyncio
async def test_initializer(proxy_factory):
    account, proxy = proxy_factory

    await signer.send_transaction(
        account, proxy.contract_address, 'initializer', [account.contract_address]
    )

    # check admin is set
    execution_info = await signer.send_transaction(
        account, proxy.contract_address, 'getAdmin', []
    )
    assert execution_info.result.response == [account.contract_address]


@pytest.mark.asyncio
async def test_initializer_after_initialized(after_initialized):
    account, proxy = after_initialized

    await assert_revert(signer.send_transaction(
        account, proxy.contract_address, 'initializer', [account.contract_address]),
        reverted_with="Proxy: contract already initialized"
    )

#
# setAdmin
#

@pytest.mark.asyncio
async def test_setAdmin(after_initialized):
    account, proxy = after_initialized

    # check initial admin
    execution_info = await signer.send_transaction(
        account, proxy.contract_address, 'getAdmin', []
    )
    assert execution_info.result.response == [account.contract_address]

    # set admin
    tx_exec_info = await signer.send_transaction(
        account, proxy.contract_address, 'setAdmin', [VALUE]
    )

    # check event
    assert_event_emitted(
        tx_exec_info,
        from_address=proxy.contract_address,
        name='AdminChanged',
        data=[
            account.contract_address,       # old admin
            VALUE                           # new admin
        ]
    )

    # check new admin
    execution_info = await signer.send_transaction(
        account, proxy.contract_address, 'getAdmin', []
    )
    assert execution_info.result.response == [VALUE]

#
# fallback function
#

@pytest.mark.asyncio
async def test_default_fallback(proxy_factory):
    account, proxy = proxy_factory

    # set value through proxy
    await signer.send_transaction(
        account, proxy.contract_address, 'setValue', [VALUE]
    )

    # get value through proxy
    execution_info = execution_info = await signer.send_transaction(
        account, proxy.contract_address, 'getValue', []
    )
    assert execution_info.result.response == [VALUE]


@pytest.mark.asyncio
async def test_fallback_when_selector_does_not_exist(proxy_factory):
    account, proxy = proxy_factory

    try:
        await signer.send_transaction(
            account, proxy.contract_address, 'bad_selector', []
        )
        raise StarkException
    except StarkException as err:
        _, error = err.args
        assert (
            f"Entry point {hex(get_selector_from_name('bad_selector'))} not found in contract" 
            in error['message']
        )
