from additional_functions import AdditionalFunctions
from state_update_function import StateUpdateFunction
from inverse_state_update_function import InverseStateUpdateFunction
from tweakable_block_cipher import TweakableBlockCipher

# THIS CLASS GENERATED FOR ORIGINAL DECRYPTION OPERATION OF THE ALGORITHM
class RomulusDecryption:
    def __init__(self):
        self.af = AdditionalFunctions()  # Initialize AdditionalFunctions instance for utility functions
        self.suf = StateUpdateFunction()  # Initialize StateUpdateFunction for state updates
        self.inv_suf = InverseStateUpdateFunction()  # Initialize InverseStateUpdateFunction for inverse state updates
        self.tbc = TweakableBlockCipher()  # Initialize TweakableBlockCipher for encryption/decryption operations

    def decryption(self, key, nonce, associated_data, ciphertext, tag_bytes):
        """
        Decrypts the given ciphertext using the Romulus-N decryption process.

        Args:
        - key (bytes): The secret key used for decryption (48 bytes).
        - nonce (bytes): The nonce (128 bits) used for decryption.
        - associated_data (bytes): The associated data (optional).
        - ciphertext (bytes): The encrypted ciphertext to be decrypted.
        - tag_bytes (bytes): The authentication tag for verifying ciphertext integrity.

        Returns:
        - bytes: The decrypted plaintext if the tag is valid.
        - None: If the tag is invalid.
        """
        # Convert the tag from bytes to bits for further processing
        tag = self.af.bytes_to_bits(tag_bytes)

        # Associated data preprocessing
        blocks = self.af.divide_input_into_blocks(self.af.pad_L(associated_data))  # Divide associated data into 16-byte blocks
        blocks = [self.af.bytes_to_bits(b) for b in blocks]  # Convert blocks from bytes to bits
        alpha = len(blocks)  # Number of blocks in associated data
        state = [0] * 128  # Initialize the state as a 128-bit zero vector

        # Process associated data blocks in pairs
        for i in range(alpha // 2):
            ad_odd = blocks[2*i]  # Odd indexed block in the pair (A1, A3, ...)
            is_last = (i == (alpha // 2) - 1) and (alpha % 2 == 0)  # Flag to check if it's the last block
            is_padded = len(associated_data) % 16 != 0  # Flag to check if the associated data is padded
            Y, _ = self.suf.state_update_function(state, ad_odd)  # Update the state using the odd block

            ad_even = blocks[2*i + 1]  # Even indexed block in the pair (A2, A4, ...)
            # Generate the tweakey for the even block using LFSR and the key
            tweakey = self.tbc.tweakey_encoding(
                key, self.af.bits_to_bytes(ad_even),
                self.tbc.lfsr56_update(list((2 * i).to_bytes(7, 'little'))),
                is_last_block=is_last, is_auth_phase=True,
                is_message_block=False, is_padded_ad=is_padded,
                is_padded_msg=False
            )

            # Apply the tweakable block cipher to the state and the even block
            if is_last and is_padded:
                padded = self.af.pad_L(self.af.unpad_L(self.af.bits_to_bytes(Y)))  # Apply padding if needed
                state, _ = self.tbc.tweakable_block_cipher_bits(self.af.bytes_to_bits(padded), tweakey)
            else:
                state, _ = self.tbc.tweakable_block_cipher_bits(Y, tweakey)

        # Handle the last block if there is an odd number of blocks
        V = blocks[-1] if alpha % 2 != 0 else [0] * 128  # Use zero block if the number of blocks is even
        Y, _ = self.suf.state_update_function(state, V)  # Update the state with the last block
        # Generate the tweakey for the last block of associated data
        tweakey = self.tbc.tweakey_encoding(
            key, nonce,
            self.tbc.lfsr56_update(list((alpha).to_bytes(7, 'little'))),
            is_last_block=False, is_auth_phase=True,
            is_message_block=False,
            is_padded_ad=(len(associated_data) % 16 != 0),
            is_padded_msg=False
        )
        state, _ = self.tbc.tweakable_block_cipher_bits(Y, tweakey)  # Apply tweakable block cipher to the state

        # Message decryption process
        blocks = self.af.divide_input_into_blocks(self.af.pad_L(ciphertext))  # Divide ciphertext into 16-byte blocks
        blocks = [self.af.bytes_to_bits(b) for b in blocks]  # Convert ciphertext blocks to bits
        μ = len(blocks)  # Number of message blocks
        plaintext = []  # Initialize the list to store the decrypted plaintext blocks

        # Iterate through the message blocks, decrypting each
        for i in range(μ - 1):
            Y, M_i = self.inv_suf.inverse_state_update_function(state, blocks[i])  # Update state and recover message block
            plaintext.append(M_i)  # Add decrypted message block to the plaintext list

            # Generate the tweakey for the current block
            tweakey = self.tbc.tweakey_encoding(
                key, nonce,
                self.tbc.lfsr56_update(list((2 * i).to_bytes(7, 'little'))),
                is_last_block=False, is_auth_phase=False,
                is_message_block=True,
                is_padded_ad=False,
                is_padded_msg=(len(ciphertext) % 16 != 0)
            )

        # Decrypt the final block
        last_block = blocks[-1]  # Last message block
        last_len = len(ciphertext) % 16  # Length of the final block (for padding handling)
        Y, M_last = self.inv_suf.inverse_state_update_function(state, last_block)  # Update state and recover final message block
        if last_len:
            M_last = M_last[:last_len * 8]  # Truncate the last block if necessary
        plaintext.append(M_last)  # Add the final decrypted block to the plaintext

        # Generate the tweakey for the last block
        tweakey = self.tbc.tweakey_encoding(
            key, nonce,
            self.tbc.lfsr56_update(list((2 * (μ - 1)).to_bytes(7, 'little'))),
            is_last_block=True, is_auth_phase=False,
            is_message_block=True,
            is_padded_ad=False,
            is_padded_msg=(last_len != 0)
        )
        state, _ = self.tbc.tweakable_block_cipher_bits(Y, tweakey)  # Apply tweakable block cipher to the state

        # Perform the final state update and check if the tag matches
        _, O_dec = self.suf.state_update_function(state, [0] * 128)  # Final state update using a zero vector
        if O_dec == tag:  # If the final state matches the tag, the decryption is successful
            # Flatten the decrypted message blocks and return the plaintext
            bits_flat = [b for block in plaintext for b in block]
            return bytes(self.af.bits_to_bytes(bits_flat))[:len(ciphertext)]
        return None  # Return None if the tag does not match (indicating a decryption failure)
