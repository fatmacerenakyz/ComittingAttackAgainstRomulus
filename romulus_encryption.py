from additional_functions import AdditionalFunctions
from state_update_function import StateUpdateFunction
from tweakable_block_cipher import TweakableBlockCipher

#THIS CLASS GENERATED FOR ENCRYPTION PROCESS
class RomulusEncryption:
    def __init__(self):
        self.additional_functions = AdditionalFunctions()
        self.state_update_function = StateUpdateFunction()
        self.tweakable_block_cipher = TweakableBlockCipher()
        

    def encryption(self, key, nonce, associated_data, message):
        """
        Performs the full encryption process: first encrypting the associated data,inverse_tweakable_block_cipher
        then encrypting the message using the final state from the associated data encryption.
        The function also generates a tag to verify the integrity of the ciphertext.
    
        Args:
        - key (bytes): The secret key used for encryption (48 bytes).
        - nonce (bytes): The nonce (initialization vector) used for encryption (16 bytes).
        - associated_data (bytes): The associated data that will be encrypted.
        - message (bytes): The plaintext message to be encrypted.
    
        Returns:
        - ciphertext (bytes): The encrypted message.
        - tag (bytes): The authentication tag for the ciphertext.
        """
        # Validate the key and nonce if they have the correct length or not
        self.additional_functions.validate_key_nonce(key, nonce)
        
        # Encrypt the associated data and obtain the initial state for message encryption
        state = self.context_encryption(key, nonce, associated_data)
        
        # Step 3: Encrypt the message and generate the tag
        ciphertext, tag_bits = self.message_encryption(key, nonce, state, message)
        
        # Step 4: Return the ciphertext and the tag
        return ciphertext, self.additional_functions.bits_to_bytes(tag_bits)  # Return the final ciphertext and the authentication tag
            
    def context_encryption(self, key, nonce, associated_data):
        """
        Encrypts the associated data and returns the initial state for message encryption. 
        This function processes the associated data in blocks and updates the state 
        with the help of tweakable block cipher. The final state is returned, which 
        is later used in message encryption.
    
        Args:
        - key (bytes): The secret key used for encryption (48 bytes).
        - nonce (bytes): The nonce (initialization vector) used for encryption (16 bytes).
        - associated_data (bytes): The associated data that will be encrypted.
    
        Returns:
        - state (list): The final 128-bit state after processing the associated data.
        """
        
        # Prepare the associated data by dividing it into 16-byte blocks
        blocks = self.additional_functions.divide_input_into_blocks(self.additional_functions.pad_L(associated_data))  # Apply padding if needed
        blocks = [self.additional_functions.bytes_to_bits(b) for b in blocks]  # Convert each to bits
        alpha = len(blocks)  # The number of 16-byte blocks
        state = [0] * 128  # Initialize the state as a 128-bit zero block
        # Process each pair of associated data blocks
        for i in range(alpha // 2):
            ad_odd = blocks[2*i]  # The odd indexed 16-byte block
            ad_even = blocks[2*i + 1]  # The even indexed 16-byte block
            
            
            is_last_block = (i == (alpha // 2) - 1) and (alpha % 2 == 0) #Checking for tweakey input
            is_padded_ad = (len(associated_data) % 16 != 0) #Checking for tweakey input
            Y, _ = self.state_update_function.state_update_function(state, ad_odd) #Odd blocks are used by state update function
            
            # Generate the tweakey for the even block using the LFSR and the key
            tweakey = self.tweakable_block_cipher.tweakey_encoding(
                key, self.additional_functions.bits_to_bytes(ad_even), self.tweakable_block_cipher.lfsr56_update(list((2*i).to_bytes(7, 'little'))), 
                is_last_block=is_last_block, 
                is_auth_phase=True, 
                is_message_block=False, 
                is_padded_ad=is_padded_ad, 
                is_padded_msg=False
            )
            state, round_tweakeys = self.tweakable_block_cipher.tweakable_block_cipher_bits(Y, tweakey)
            
        # Process the last associated data block if the total number of blocks is odd
        # 128-bit zero block if the total number of blocks is even
        V = blocks[-1] if alpha % 2 != 0 else [0] * 128 
        # Perform state update on the last block (or zero block if padding is applied)
        Y, _ = self.state_update_function.state_update_function(state, V)
        # Generate the tweakey for the final block of associated data (using the current alpha count-1)
        # This tweakey inputs must be matched with the adversary part in a reverse order
        tweakey = self.tweakable_block_cipher.tweakey_encoding(
            key, nonce, self.tweakable_block_cipher.lfsr56_update(list((alpha-1).to_bytes(7, 'little'))), 
            is_last_block=False, #because this is an additional block
            is_auth_phase=True, 
            is_message_block=False, 
            is_padded_ad=(len(associated_data) % 16 != 0), 
            is_padded_msg=False
        )

        state, _ = self.tweakable_block_cipher.tweakable_block_cipher_bits(Y, tweakey)
        return state  # Return the final state after processing the associated data
    
    def message_encryption(self, key, nonce, state, message):
        """
        Encrypts the message using the final state from the associated data encryption. 
        This function processes the message in blocks and updates the state for each block. 
        The ciphertext is generated by XORing the state with each message block. 
        The function also generates the tag for the encrypted message.
    
        Args:
        - key (bytes): The secret key used for encryption (48 bytes).
        - nonce (bytes): The nonce (initialization vector) used for encryption (16 bytes).
        - state (list): The final 128-bit state from the associated data encryption.
        - message (bytes): The plaintext message to be encrypted.
    
        Returns:
        - ciphertext (bytes): The encrypted message.
        - tag (bytes): The authentication tag for the ciphertext.
        """
        # Step 1: Divide the message into 16-byte blocks for encryption
        # Padding is applied to the message
        blocks = self.additional_functions.divide_input_into_blocks(self.additional_functions.pad_L(message))
        blocks = [self.additional_functions.bytes_to_bits(b) for b in blocks]
        
        μ = len(blocks)  # The number of message blocks
        ciphertext = []  # The list to store the encrypted ciphertext blocks
        
        # Step 2: Encrypt each block except the last one
        for i in range(μ - 1):

            # Perform state update and retrieve the encrypted ciphertext block
            Y, C_i = self.state_update_function.state_update_function(state, blocks[i])
            ciphertext.append(self.additional_functions.bits_to_bytes(C_i))
            
            # Generate the tweakey for the current block using LFSR and the key
            tweakey = self.tweakable_block_cipher.tweakey_encoding(
                key, nonce, self.tweakable_block_cipher.lfsr56_update(list((2*i).to_bytes(7, 'little'))),
                is_last_block=False, 
                is_auth_phase=False, 
                is_message_block=True, 
                is_padded_ad=False, 
                is_padded_msg=(len(message) % 16 != 0)
            )
            state, _ = self.tweakable_block_cipher.tweakable_block_cipher_bits(Y, tweakey)

        # Step 3: Encrypt the last message block
        Y, C_last = self.state_update_function.state_update_function(state, blocks[-1])
        ciphertext.append(self.additional_functions.bits_to_bytes(C_last))  # Append the last ciphertext block
        
        # Step 4: Generate the tweakey for the last block
        is_padded_msg = (len(message) % 16 != 0)
        tweakey = self.tweakable_block_cipher.tweakey_encoding(
            key, nonce, self.tweakable_block_cipher.lfsr56_update(list((2 * (μ - 1)).to_bytes(7, 'little'))),
            is_last_block=True, 
            is_auth_phase=False, 
            is_message_block=True, 
            is_padded_ad=False, 
            is_padded_msg=is_padded_msg
        )

        state, _ = self.tweakable_block_cipher.tweakable_block_cipher_bits(Y, tweakey)
        # Step 5: Generate the tag from the final state
        _, tag_bits = self.state_update_function.state_update_function(state, [0] * 128)
        
        #combine the all ciphertext blocks in one block and take the same length as the message
        final_ciphertext = b''.join(bytes(block) for block in ciphertext)[:len(message)]

        return final_ciphertext, tag_bits
