from additional_functions import AdditionalFunctions
from tweakable_block_cipher import TweakableBlockCipher

from copy import deepcopy

class InverseTweakableBlockCipher:
    def __init__(self):
        self.additional_functions = AdditionalFunctions()
        self.tweakable_block_cipher = TweakableBlockCipher()
        self.mix_matrix = self.tweakable_block_cipher.mix_matrix
        
    def inverse_S8(self):
        """
        Inverse of the S8 substitution box used in the cipher.
        This method constructs the inverse of the S8 substitution table by mapping 
        each byte in the S8 table to its corresponding inverse index. It allows reversing 
        the substitution step in the decryption process.
    
        Returns:
        - S8_inv (list): The inverse S8 substitution box where each byte in the original
                          S8 table is mapped to its index, effectively reversing the substitution.
        """
        S8_inv = [0] * 256  # Initialize a list of size 256 to store the inverse S8 table
    
        # Iterate over each byte in the S8 table
        for i in range(256):
            # For each value in the S8 table, map it to the index in the inverse S8 table
            S8_inv[self.additional_functions.S8[i]] = i
    
        return S8_inv  # Return the constructed inverse S8 table
    
    def invert_binary_matrix(self, matrix):
        """
        Inverts a binary matrix over GF(2).
        This function uses Gaussian elimination to invert the matrix over GF(2) (Galois Field 2),
        which is used in cryptographic operations for matrix transformations.
    
        Args:
            matrix (list of list of int): An n x n matrix with elements in {0, 1}
                                          (binary matrix over GF(2)).
    
        Returns:
            list of list of int: The inverse of the input matrix over GF(2), if invertible.
                                  The result will also be a binary matrix (with elements in {0, 1}).
    
        Raises:
            ValueError: If the matrix is not square (i.e., not n x n) or if the matrix is not invertible in GF(2).
        """
        n = len(matrix)  # Get the size of the matrix (n x n)
        
        # Ensure the matrix is square (same number of rows and columns)
        if any(len(row) != n for row in matrix):
            raise ValueError("Matrix must be square")  # Raise an error if the matrix is not square
        
        # Create a copy of the input matrix (A) and the identity matrix (I)
        A = [row[:] for row in matrix]  # Copy of the input matrix to modify during Gaussian elimination
        I = [[int(i == j) for j in range(n)] for i in range(n)]  # Identity matrix of size n x n
        
        # Perform Gaussian elimination to compute the inverse
        for i in range(n):
            # If the diagonal element is 0, swap rows with a row below where the element is 1
            if A[i][i] == 0:
                for j in range(i + 1, n):
                    if A[j][i] == 1:
                        A[i], A[j] = A[j], A[i]  # Swap rows in A
                        I[i], I[j] = I[j], I[i]  # Swap rows in I (identity matrix)
                        break
                else:
                    raise ValueError("Matrix is not invertible over GF(2)")  # If no swap is possible, matrix is not invertible
            
            # Eliminate all elements below the diagonal (make them 0) by XORing rows
            for j in range(n):
                if i != j and A[j][i] == 1:  # If the current element is 1 and not on the diagonal
                    for k in range(n):
                        A[j][k] ^= A[i][k]  # XOR row j with row i in matrix A
                        I[j][k] ^= I[i][k]  # XOR corresponding row in identity matrix I
        
        return I  # Return the inverse matrix (identity matrix after Gaussian elimination)

    
    def inverse_mix_columns_binary(self, state):
        """
        Applies the inverse MixColumns operation on the state matrix (binary version).
        The operation is designed to undo the column mixing used in the encryption process.
    
        Args:
        - state (list of list of int): The 4x4 state matrix.
    
        Returns:
        - new_state (list of list of int): The state matrix after the inverse MixColumns operation.
        """
        # Invert the mix matrix (GF(2) operations)
        inv_M = self.invert_binary_matrix(self.mix_matrix)
        new_state = [[0]*4 for _ in range(4)]  # Initialize the new state matrix
    
        # Iterate over each column in the state matrix
        for col in range(4):
            column = [state[row][col] for row in range(4)]  # Extract the column
            for row in range(4):  # For each row in the new column
                val = 0
                for k in range(4):
                    # Apply XOR for matrix multiplication
                    if inv_M[row][k]:
                        val ^= column[k]
                new_state[row][col] = val  # Assign the result to the new state
    
        return new_state  # Return the updated state matrix
    
    
    def inverse_mix_columns(self, state):
        """
        Applies the inverse MixColumns operation on the state matrix (GF(2⁸) version).
        This operation is designed to undo the mixing of columns over GF(2⁸).
    
        Args:
        - state (list of list of int): The 4x4 state matrix.
    
        Returns:
        - new_state (list of list of int): The state matrix after the inverse MixColumns operation.
        """
        # Inverse MixMatrix used for GF(2⁸) operations
        inv_matrix = self.inv_mix_matrix
        new_columns = []
    
        # Process each column individually
        for i in range(4):
            column = [state[row][i] for row in range(4)]  # Extract the column
            new_column = []
    
            # For each row, apply GF(2⁸) multiplication and XORing
            for row in range(4):
                value = 0
                for col in range(4):
                    value ^= self.tweakable_block_cipher.multiply_gf(inv_matrix[row][col], column[col])  # GF(2⁸) multiplication
                new_column.append(value & 0xFF)  # Store the result in the new column
    
            new_columns.append(new_column)  # Add the new column to the list
    
        # Convert the columns back into rows (transpose the matrix)
        new_state = [[new_columns[j][i] for j in range(4)] for i in range(4)]
        return new_state  # Return the new state matrix
    
    
    def inverse_shift_rows(self, state):
        """
        Applies the inverse ShiftRows operation on the state matrix.
        This operation shifts each row of the state to the right (undoing the left shift in the encryption).
    
        Args:
        - state (list of list of int): The 4x4 state matrix.
    
        Returns:
        - state (list of list of int): The state matrix after applying the inverse ShiftRows operation.
        """
        # The first row remains unchanged (no shift)
        state[0] = state[0]
        # Shift each row to the right (inverse of ShiftRows in encryption)
        state[1] = state[1][1:] + state[1][:1]  # 1 byte shift right
        state[2] = state[2][2:] + state[2][:2]  # 2 bytes shift right
        state[3] = state[3][3:] + state[3][:3]  # 3 bytes shift right
    
        return state  # Return the modified state matrix
    
    
    def inverse_sub_cells(self, state):
        """
        Applies the inverse SubCells operation on the state matrix.
        The operation uses the inverse of the S8 substitution box to reverse the substitution process.
    
        Args:
        - state (list of list of int): The 4x4 state matrix.
    
        Returns:
        - state (list of list of int): The state matrix after applying the inverse SubCells operation.
        """
        # Get the inverse S8 substitution box
        S8_inv = self.inverse_S8()
        # Apply the inverse substitution to each byte in the state matrix
        return [[S8_inv[byte] for byte in row] for row in state]
    
    
    def inverse_tweakable_cipher(self, ciphertext, round_tweakeys):
        """
        Applies the inverse of the tweakable block cipher to decrypt the given ciphertext.
        This process is the reverse of the encryption process and involves applying the inverse 
        of each operation in the encryption (Inverse MixColumns, Inverse ShiftRows, AddRoundTweakey, etc.).
    
        Args:
        - ciphertext (bytes): The ciphertext to decrypt.
        - round_tweakeys (list): The round tweakeys used for the decryption process.
    
        Returns:
        - list: The decrypted message as a list of bits.
        """
        # Convert ciphertext into a matrix (4x4 form)
        state = self.additional_functions.block_to_matrix(ciphertext)
    
        # Iterate over each round in reverse order (from round 40 to round 1)
        for round_number in reversed(range(1, 41)):
            # Apply inverse MixColumns operation (except for the last round)
            if round_number < 40:
                state = self.inverse_mix_columns_binary(state)
            
            # Apply inverse ShiftRows operation
            state = self.inverse_shift_rows(state)
    
            # Get the tweakey matrices for this round
            tweakey_matrices = round_tweakeys[round_number - 1]
    
            # Apply AddRoundTweakey operation to the state
            state, tweakey_matrices = self.tweakable_block_cipher.add_round_tweakey(state, deepcopy(tweakey_matrices))
    
            # Add round constants to the state
            round_constants_matrix = self.tweakable_block_cipher.add_constants(state, round_number)
            state = self.additional_functions.xor_matrices(state, round_constants_matrix)
    
            # Apply inverse SubCells operation
            state = self.inverse_sub_cells(state)
    
        # Convert the final state matrix back to bytes and then to bits
        decrypted_bytes = self.additional_functions.matrix_to_block(state)
        decrypted_bits = self.additional_functions.bytes_to_bits(decrypted_bytes)
    
        return decrypted_bits  # Return the decrypted message as a bit list
