from additional_functions import AdditionalFunctions
from copy import deepcopy

class TweakableBlockCipher:
    def __init__(self):
        self.additional_functions = AdditionalFunctions()
        self.S8 = self.additional_functions.S8
        self.mix_matrix = [
            [1, 0, 1, 1],
            [1, 0, 0, 0],
            [0, 1, 1, 0],
            [1, 0, 1, 0]
        ]
        
    def sub_cells(self, state):
        """
        Substitutes the bytes in the state matrix using the S8 substitution box. 
        This operation replaces each byte in the state with a corresponding byte 
        from the S8 table.
    
        Args:
        - state (list): A 4x4 matrix (list of lists) containing the current state.
    
        Returns:
        - list: A new 4x4 matrix after substituting the bytes using the S8 table.
        """
        return [[self.S8[byte] for byte in row] for row in state]
    
    class AffineLFSR_add_constant:
        """
        This class implements an Affine Linear Feedback Shift Register (LFSR) with an additional constant.
        The LFSR is used to generate round constants for cryptographic operations.
    
        Attributes:
        - state (list): The state of the LFSR, represented as a list of 6 bits (rc5, rc4, rc3, rc2, rc1, rc0).
        """
        def __init__(self):
            """Initializes the LFSR state to all zeros."""
            self.state = [0, 0, 0, 0, 0, 0]  # rc5, rc4, rc3, rc2, rc1, rc0
    
        def update(self):
            """
            Updates the state of the LFSR. The new bit is calculated as the XOR of the first two bits (rc5 and rc4)
            and the constant '1'. The state is then shifted left and the new bit is appended at the end.
            """
            new_bit = self.state[0] ^ self.state[1] ^ 1  # rc5 XOR rc4 XOR 1
            self.state = self.state[1:] + [new_bit]
    
        def get_round_constant(self, round_idx, round_constants):
            """
            Retrieves the round constant for a given round index from the list of round constants.
            
            Args:
            - round_idx (int): The index of the round constant to retrieve.
            - round_constants (list): A list of round constants in hexadecimal format.
    
            Returns:
            - int: The round constant corresponding to the provided index.
            """
            return int(round_constants[round_idx], 16)
    
        def hex_to_bin(self, hex_str):
            """
            Converts a hexadecimal string to a binary list of bits.
    
            Args:
            - hex_str (str): The hexadecimal string to convert.
    
            Returns:
            - list: A list of binary bits representing the input hexadecimal string.
            """
            return [int(b) for b in bin(int(hex_str, 16))[2:].zfill(6)]  # 6-bit binary representation
        
    def add_constants(self, state, round_number):
        """
        Adds the round constant to the state based on the current round number. 
        This function retrieves the appropriate round constant from predefined lists, 
        and generates the values c0, c1, and c2 to update the state.
    
        Args:
        - state (list): The current state (4x4 matrix) that will be modified.
        - round_number (int): The current round number, which determines the round constant.
    
        Returns:
        - list: The updated state with the round constant added.
        """
        if 1 <= round_number <= 16:
            round_constants = ['01', '03', '07', '0F', '1F', '3E', '3D', 'B', '37', '2F', '1E', '3C', '39', '33', '27', '0E']
            index = round_number - 1
        elif 17 <= round_number <= 32:
            round_constants = ['1D', '3A', '35', '2B', '16', '2C', '18', '30', '21', '02', '05', '0B', '17', '2E', '1C', '38']
            index = round_number - 17
        elif 33 <= round_number <= 40:
            round_constants = ['31', '23', '06', '0D', '1B', '36', '2D', '1A']
            index = round_number - 33
        else:
            raise ValueError("Round number out of range")
            
        lfsr = self.AffineLFSR_add_constant()
        round_constant = lfsr.get_round_constant(index, round_constants)
        c0 = round_constant & 0x0F
        c1 = round_constant & 0xC0
        c2 = 0x2
        
        new_state = [[c0, 0, 0, 0], [c1, 0, 0, 0], [c2, 0, 0, 0], [0, 0, 0, 0]]
        return new_state
    
    def permute_tweakey_matrix(self, matrix, permutation):
        """
        Permutes the given 4x4 tweakey matrix based on the specified permutation list.
    
        Args:
        - matrix (list): A 4x4 matrix to be permuted.
        - permutation (list): A list defining the permutation order for the matrix.
    
        Returns:
        - list: The permuted 4x4 matrix.
        """
        flat = sum(matrix, [])
        permuted = [flat[permutation[i]] for i in range(16)]
        return [permuted[i*4:(i+1)*4] for i in range(4)]
    
    def lfsr_tk2(self, tk):
        """
        Updates TK2 using an LFSR with feedback from bits x7 and x5.
        
        Args:
        - tk (list): A list representing the tweakey (16 bytes).
    
        Returns:
        - list: A new 16-byte list representing the updated TK2.
        """
        return [((tk[i] << 1) ^ (((tk[i] >> 7) ^ (tk[i] >> 5)) & 1)) & 0xFF for i in range(16)]
    
    def lfsr_tk3(self, tk):
        """
        Updates TK3 using an LFSR with feedback from bits x0 and x6.
        
        Args:
        - tk (list): A list representing the tweakey (16 bytes).
    
        Returns:
        - list: A new 16-byte list representing the updated TK3.
        """
        return [((tk[i] >> 1) ^ (((tk[i] & 1) ^ ((tk[i] >> 6) & 1)) << 7)) & 0xFF for i in range(16)]
    
    def add_round_tweakey(self, state, tweakey_matrices):
        """
        Applies the round tweakey to the first two rows of the state using the tweakey matrices. 
        Then applies a permutation to the tweakey matrices and updates them using LFSR.
    
        Args:
        - state (list): The current state matrix (4x4).
        - tweakey_matrices (list): The list of three 4x4 tweakey matrices (TK1, TK2, TK3).
    
        Returns:
        - list: The updated state matrix.
        - list: The updated tweakey matrices.
        """
        for i in range(2):
            for j in range(4):
                state[i][j] ^= (
                    tweakey_matrices[0][i][j]
                    ^ tweakey_matrices[1][i][j]
                    ^ tweakey_matrices[2][i][j]
                ) % 256  # Ensures the value is within byte range
        
        # Apply permutation to the tweakey matrices
        P_t = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7]
        tweakey_matrices[0] = self.permute_tweakey_matrix(tweakey_matrices[0], P_t)
        tweakey_matrices[1] = self.permute_tweakey_matrix(tweakey_matrices[1], P_t)
        tweakey_matrices[2] = self.permute_tweakey_matrix(tweakey_matrices[2], P_t)
    
        # Update TK2 and TK3 using LFSR
        flat_tk2 = sum(tweakey_matrices[1], [])
        flat_tk3 = sum(tweakey_matrices[2], [])
        updated_tk2 = self.lfsr_tk2(flat_tk2)  # Update TK2
        updated_tk3 = self.lfsr_tk3(flat_tk3)  # Update TK3
    
        # Convert the updated lists back to 4x4 matrices
        tweakey_matrices[1] = [updated_tk2[i*4:(i+1)*4] for i in range(4)]
        tweakey_matrices[2] = [updated_tk3[i*4:(i+1)*4] for i in range(4)]
        return state, tweakey_matrices
    
    def shift_rows(self, state):
        """
        Performs the 'ShiftRows' operation on the state, shifting each row of the state 
        by a certain number of bytes to the left. The first row remains unchanged, the second 
        row is shifted by 1 byte, the third row by 2 bytes, and the fourth row by 3 bytes.
    
        Args:
        - state (list): The state matrix (4x4).
    
        Returns:
        - list: The state matrix after shifting the rows.
        """
        state[0] = state[0]  # Row 0 remains unchanged
        state[1] = state[1][-1:] + state[1][:-1]  # Shift second row by 1 byte
        state[2] = state[2][-2:] + state[2][:-2]  # Shift third row by 2 bytes
        state[3] = state[3][-3:] + state[3][:-3]  # Shift fourth row by 3 bytes
        return state
    
    def mix_columns_binary(self, state):

        new_state = [[0]*4 for _ in range(4)]
    
        for col in range(4):
            column = [state[row][col] for row in range(4)]
            for row in range(4):
                val = 0
                for k in range(4):
                    if self.mix_matrix[row][k]:
                        val ^= column[k]
                new_state[row][col] = val
        return new_state
    
    def tweakable_block_cipher(self, message, tweakey_bytes):
        """
        Applies the tweakable block cipher on the given message using the provided tweakey bytes.
    
        Args:
        - message (bytes): The message to be encrypted or decrypted.
        - tweakey_bytes (bytes): The 48-byte tweakey.
    
        Returns:
        - list: The encrypted message as a list of bytes.
        - list: The updated tweakey matrices.
        """
        state = self.additional_functions.block_to_matrix(message)
        tweakey_matrices = self.additional_functions.tweakey_to_matrices(tweakey_bytes)
        round_tweakeys = [] #original tweakeys for using inverse function
        for round_number in range(1, 41):
            round_tweakeys.append(deepcopy(tweakey_matrices))
            state = self.sub_cells(state)
            round_constants_matrix = self.add_constants(state, round_number)
            state = self.additional_functions.xor_matrices(state, round_constants_matrix)
            state, tweakey_matrices = self.add_round_tweakey(state, tweakey_matrices)
            state = self.shift_rows(state)
            if round_number < 40:
                state = self.mix_columns_binary(state)
        return self.additional_functions.matrix_to_block(state), round_tweakeys
    
    #USED WHILE GENERATING TWEAKEY BEFORE TBC INSIDE ENC OR DEC OR ADV
    def lfsr56_update(self, byte_list):
        """
        Updates a 56-bit LFSR (Linear Feedback Shift Register) using the provided 7-byte input list.
        The function calculates the next state of the LFSR and returns it as a new 7-byte list.
    
        Args:
        - byte_list (list): The 7-byte input list representing the current state of the LFSR.
    
        Returns:
        - list: A new 7-byte list representing the updated state of the LFSR.
        """
        num = 0
        for i in range(7):
            num |= byte_list[i] << (8 * i)
    
        bits = [((num >> i) & 1) for i in range(56)]
        new_bits = bits[:]
    
        for i in range(55, 0, -1):
            if i not in [7, 4, 2, 0]:
                new_bits[i] = bits[i - 1]
    
        new_bits[7] = bits[6] ^ bits[55]
        new_bits[4] = bits[3] ^ bits[55]
        new_bits[2] = bits[1] ^ bits[55]
        new_bits[0] = bits[55]
    
        new_num = 0
        for i in range(56):
            new_num |= new_bits[i] << i
    
        new_byte_list = [(new_num >> (8 * i)) & 0xFF for i in range(7)]
        return new_byte_list
    
    def assigning_domain_byte(self, is_last_block, is_auth_phase, is_message_block, is_padded_ad, is_padded_msg):
        """
        Assigns a domain byte based on the given flags that specify the block type, 
        whether it is part of an authentication phase, and other conditions.
        
        Args:
        - is_last_block (bool): Flag indicating if this is the last block.
        - is_auth_phase (bool): Flag indicating if the operation is in the authentication phase.
        - is_message_block (bool): Flag indicating if the block is a message block.
        - is_padded_ad (bool): Flag indicating if the associated data is padded.
        - is_padded_msg (bool): Flag indicating if the message is padded.
        
        Returns:
        - int: The domain byte as an integer.
        """
        bits = [0, 0, 0]  # b7 b6 b5 = 000 for Romulus-N
        bits.append(1 if is_last_block else 0)
        bits.append(1 if is_auth_phase else 0)
        bits.append(1 if is_message_block else 0)
        bits.append(1 if is_padded_ad else 0)
        bits.append(1 if is_padded_msg else 0)
        domain_byte = sum((bit << (7 - i)) for i, bit in enumerate(bits))
        return domain_byte
    
    def tweakey_encoding(self, full_key_48, tweak, counter_bytes, is_last_block, is_auth_phase, is_message_block, is_padded_ad, is_padded_msg):
        """
        Encodes the tweakey by combining the counter bytes, domain byte, tweak, 
        and the final part of the full key (TK3) into a single list of bytes.
    
        Args:
        - full_key_48 (bytes): The 48-byte full key used for encryption.
        - tweak (bytes): The 16-byte tweak to be used.
        - counter_bytes (bytes): The 7-byte counter value used for encoding.
        - is_last_block (bool): Flag indicating if this is the last block.
        - is_auth_phase (bool): Flag indicating if the operation is in the authentication phase.
        - is_message_block (bool): Flag indicating if the block is a message block.
        - is_padded_ad (bool): Flag indicating if the associated data is padded.
        - is_padded_msg (bool): Flag indicating if the message is padded.
        
        Returns:
        - list: A list representing the tweakey.
        """
        assert len(full_key_48) == 48, "Expected 48-byte full key"
        assert len(tweak) == 16
        assert len(counter_bytes) == 7
    
        domain_byte = self.assigning_domain_byte(is_last_block, is_auth_phase, is_message_block, is_padded_ad, is_padded_msg)
        tk1 = counter_bytes + [domain_byte] + [0] * 8
        tk2 = list(tweak)
        tk3 = list(full_key_48[32:])  # Last 16 bytes (main key)
        return tk1 + tk2 + tk3
    
    #This function will call, to receive bit-wise outputs
    def tweakable_block_cipher_bits(self, message_bits, tweakey_bytes):
        """
        Bit-level wrapper for tweakable_block_cipher.
        Converts 128-bit input to bytes, processes, and returns 128-bit result.
        """
        message_bytes = self.additional_functions.bits_to_bytes(message_bits)
        ciphertext_bytes, round_tweakeys = self.tweakable_block_cipher(message_bytes, tweakey_bytes)
        ciphertext_bits = self.additional_functions.bytes_to_bits(ciphertext_bytes)
        return ciphertext_bits, round_tweakeys