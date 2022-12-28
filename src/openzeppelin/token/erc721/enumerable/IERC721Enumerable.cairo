// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts for Cairo v0.6.0 (token/erc721/enumerable/IERC721Enumerable.cairo)

%lang starknet

from starkware.cairo.common.uint256 import Uint256

@contract_interface
namespace IERC721Enumerable {
    func totalSupply() -> (totalSupply: Uint256) {
    }

    func tokenByIndex(index: Uint256) -> (tokenId: Uint256) {
    }

    func tokenOfOwnerByIndex(owner: felt, index: Uint256) -> (tokenId: Uint256) {
    }

    /// IERC721

    func balanceOf(owner: felt) -> (balance: Uint256) {
    }

    func ownerOf(tokenId: Uint256) -> (owner: felt) {
    }

    func safeTransferFrom(from_: felt, to: felt, tokenId: Uint256, data_len: felt, data: felt*) {
    }

    func transferFrom(from_: felt, to: felt, tokenId: Uint256) {
    }

    func approve(approved: felt, tokenId: Uint256) {
    }

    func setApprovalForAll(operator: felt, approved: felt) {
    }

    func getApproved(tokenId: Uint256) -> (approved: felt) {
    }

    func isApprovedForAll(owner: felt, operator: felt) -> (approved: felt) {
    }

    // ERC165

    func supportsInterface(interfaceId: felt) -> (success: felt) {
    }
}
