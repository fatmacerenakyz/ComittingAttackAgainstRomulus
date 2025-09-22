from state_update_function import StateUpdateFunction

class InverseStateUpdateFunction:
    def __init__(self):
        self.suf = StateUpdateFunction()  # Create an instance of the StateUpdateFunction class
        self.n_blocks = 16  # The number of blocks used in the Romulus-N algorithm
        self.block_size = 8  # The block size in bits (set to 8 bits)
        self.n = self.n_blocks * self.block_size  # Total number of bits (128 bits)

        # F_s is a matrix made of 8x8 blocks, used in the Romulus-N algorithm
        self.F_s = [
            [0,0,0,0,0,0,0,1],
            [1,0,0,0,0,0,0,1],
            [1,1,0,0,0,0,0,1],
            [1,1,1,0,0,0,0,1],
            [1,1,1,1,0,0,0,1],
            [1,1,1,1,1,0,0,1],
            [1,1,1,1,1,1,0,1],
            [1,1,1,1,1,1,1,1],
        ]
        # Construct the block diagonal matrix F using the F_s blocks
        self.F = self.build_block_diagonal(self.F_s, self.n_blocks)
        # Identity matrix of size n (used for matrix inversion)
        self.I = self.identity(self.n)
        # XOR of the F matrix and identity matrix
        self.F_plus_I = self.xor_matrix(self.F, self.I)
        # Compute the inverse of F matrix in GF(2)
        self.F_inv = self.invert_matrix_mod2(self.F)
        # Multiply F_plus_I and F_inv to get G_inv
        self.G_inv = self.multiply_matrices(self.F_plus_I, self.F_inv)

    def invert_G(self, T):
        """
        Computes the inverse of the G matrix and applies it to the given vector T.
        
        Args:
        - T (list of int): A 128-bit vector.
        
        Returns:
        - list: The result of applying the inverse of G matrix to the vector T.
        
        Raises:
        - ValueError: If the vector T is not 128 bits, it raises an error.
        """
        if len(T) != self.n:
            raise ValueError("T must be 128 bits")  # T vector must be of length 128 bits
    
        # Create the actual G matrix used in the system
        G = self.suf.create_G_matrix(16)          
        # Calculate the inverse of the G matrix
        G_inv = self.invert_matrix_mod2(G)    
        # Apply the inverse of G matrix to the vector T
        return self.apply_matrix(G_inv, T)    # Apply the inverse matrix to the vector T

    def inverse_state_update_function(self, Y, C):
        """
        Performs the inverse state update function: S = (Y ⊕ C), M = (Y ⊕ S).
        
        Args:
        - Y (list of int): A 128-bit vector.
        - C (list of int): A 128-bit vector.
        
        Returns:
        - tuple: (S, M), where S is the state vector, and M is the message vector.
        
        Raises:
        - ValueError: If either Y or C are not 128-bit vectors.
        """
        if len(Y) != self.n or len(C) != self.n:
            raise ValueError("Inputs must be 128-bit vectors")  # Both Y and C must be 128 bits
        # XOR Y and C to get the intermediate state V
        V = self.xor_vectors(Y, C)
        # Apply inverse E matrix to the intermediate state
        S = self.apply_inverse_E(V)
        # XOR Y and S to get the original message M
        M = self.xor_vectors(Y, S)
        return S, M

    # === INTERNAL HELPERS ===

    def xor_vectors(self, a, b):
        """
        XORs two vectors element-wise.
        
        Args:
        - a (list of int): The first vector.
        - b (list of int): The second vector.
        
        Returns:
        - list of int: The resulting vector after applying XOR element-wise.
        """
        return [x ^ y for x, y in zip(a, b)]  # XOR corresponding elements of the vectors

    def identity(self, n):
        """
        Creates an identity matrix of size n x n.
        
        Args:
        - n (int): The size of the identity matrix.
        
        Returns:
        - list of list of int: The identity matrix of size n x n.
        """
        return [[1 if i == j else 0 for j in range(n)] for i in range(n)]  # Create identity matrix

    def xor_matrix(self, A, B):
        """
        XORs two matrices element-wise.
        
        Args:
        - A (list of list of int): The first matrix.
        - B (list of list of int): The second matrix.
        
        Returns:
        - list of list of int: The resulting matrix after applying XOR element-wise.
        """
        return [[A[i][j] ^ B[i][j] for j in range(len(A[0]))] for i in range(len(A))]  # XOR corresponding elements of matrices

    def build_block_diagonal(self, block, count):
        """
        Creates a block diagonal matrix by repeating a given block a specified number of times.
        
        Args:
        - block (list of list of int): The block to be repeated.
        - count (int): The number of times the block should be repeated.
        
        Returns:
        - list of list of int: The block diagonal matrix.
        """
        size = len(block)  # Size of the block
        n = size * count   # Size of the resulting matrix
        matrix = [[0] * n for _ in range(n)]  # Initialize the matrix with zeros
        # Place the block along the diagonal
        for b in range(count):
            for i in range(size):
                for j in range(size):
                    matrix[size * b + i][size * b + j] = block[i][j]
        return matrix  # Return the block diagonal matrix

    def apply_matrix(self, M, v):
        """
        Applies a matrix to a vector by performing matrix-vector multiplication.
        
        Args:
        - M (list of list of int): The matrix to apply.
        - v (list of int): The vector to apply the matrix to.
        
        Returns:
        - list of int: The resulting vector after applying the matrix.
        """
        return [sum((a & b) for a, b in zip(row, v)) % 2 for row in M]  # Matrix-vector multiplication in GF(2)

    def multiply_matrices(self, A, B):
        """
        Multiplies two matrices in GF(2).
        
        Args:
        - A (list of list of int): The first matrix.
        - B (list of list of int): The second matrix.
        
        Returns:
        - list of list of int: The resulting matrix after multiplying A and B.
        """
        n, m, p = len(A), len(B), len(B[0])
        result = [[0] * p for _ in range(n)]  # Initialize the result matrix
        # Perform matrix multiplication in GF(2)
        for i in range(n):
            for j in range(p):
                result[i][j] = sum(A[i][k] & B[k][j] for k in range(m)) % 2
        return result  # Return the resulting matrix

    def invert_matrix_mod2(self, M):
        """
        Inverts a matrix over GF(2).
        
        Args:
        - M (list of list of int): The matrix to invert.
        
        Returns:
        - list of list of int: The inverse of the matrix.
        
        Raises:
        - ValueError: If the matrix is not invertible in GF(2).
        """
        n = len(M)
        A = [row[:] for row in M]  # Make a copy of the matrix
        I = self.identity(n)  # Identity matrix of the same size
        # Perform Gaussian elimination to invert the matrix
        for col in range(n):
            if A[col][col] == 0:
                for row in range(col + 1, n):
                    if A[row][col] == 1:
                        A[col], A[row] = A[row], A[col]
                        I[col], I[row] = I[row], I[col]
                        break
                else:
                    raise ValueError("Matrix is not invertible over GF(2)")
            # Perform row reduction
            for row in range(n):
                if row != col and A[row][col] == 1:
                    A[row] = [a ^ b for a, b in zip(A[row], A[col])]
                    I[row] = [a ^ b for a, b in zip(I[row], I[col])]
        return I  # Return the inverted matrix

    def build_inverse_E_matrix(self):
        """
        Builds a 256x256 matrix for the inverse E transformation used in the Romulus-N algorithm.
        
        Returns:
        - list of list of int: The 256x256 matrix.
        """
        top = [row + row for row in self.F]  # [F | F]
        bottom = [row1 + row2 for row1, row2 in zip(self.F_plus_I, self.F)]  # [F + I | F]
        return top + bottom  # Combine top and bottom to form the full matrix

    def apply_inverse_E(self, V):
        """
        Applies the inverse of the E matrix to the vector V.
        
        Args:
        - V (list of int): The vector to apply the inverse E matrix to.
        
        Returns:
        - list of int: The result after applying the inverse E matrix to V.
        """
        E_inv = self.build_inverse_E_matrix()  # Build the inverse E matrix
        return [sum((a & b) for a, b in zip(row, V)) % 2 for row in E_inv[:self.n]]  # Matrix-vector multiplication in GF(2)
