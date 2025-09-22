from additional_functions import AdditionalFunctions

class StateUpdateFunction:
    def __init__(self):
        self.additional_functions = AdditionalFunctions()  # Create an instance of AdditionalFunctions class
        self.G_s = self.additional_functions.G_s  # G_s is a predefined matrix used in the Romulus-N algorithm
        self.block_size = 128  # Block size is set to 128 bits (16 bytes)

    def create_G_matrix(self, num_blocks):
        """
        Creates a G matrix that is used in the Romulus state update function.

        The matrix is built from the G_s matrix, which is a basic structure used for this transformation.

        Args:
        - num_blocks (int): The number of blocks for the G matrix.

        Returns:
        - list of list of int: The resulting G matrix of size (block_size * num_blocks) x (block_size * num_blocks).
        """
        block_size = len(self.G_s)  # Block size based on G_s matrix
        n = block_size * num_blocks  # Total size of the resulting G matrix
        G = [[0 for _ in range(n)] for _ in range(n)]  # Initialize an empty matrix of size n x n
        # Populate the G matrix with the values from the G_s matrix
        for b in range(num_blocks):
            for i in range(block_size):
                for j in range(block_size):
                    G[b*block_size + i][b*block_size + j] = self.G_s[i][j]
        return G  # Return the populated G matrix
    
    def binary_matrix_vector_mult(self, matrix, vector):
        """
        Multiplies a binary matrix with a binary vector using matrix-vector multiplication in GF(2).

        Args:
        - matrix (list of list of int): The matrix to multiply with the vector.
        - vector (list of int): The vector to multiply with the matrix.

        Returns:
        - list of int: The resulting vector after multiplication.
        """
        # Perform binary matrix-vector multiplication (sum of element-wise AND in GF(2))
        return [sum(a & b for a, b in zip(row, vector)) % 2 for row in matrix]

    def state_update_function(self, state_bits, message_bits):
        """
        Performs the Romulus state update: Y = S ⊕ I, O = G(S) ⊕ I.
        
        This function updates the state by applying XOR operations and matrix multiplications.
        
        Args:
        - state_bits (list of int): The current state represented as a 128-bit vector.
        - message_bits (list of int): The message represented as a 128-bit vector.

        Returns:
        - tuple: (Y, O), where:
            - Y is the updated state after the XOR operation.
            - O is the output after applying the G matrix to the state and XORing with the message.
        """
        G = self.create_G_matrix(16)  # Create the G matrix for this operation
        G_S = self.binary_matrix_vector_mult(G, state_bits)  # Perform matrix-vector multiplication: G(S)
        O = self.additional_functions.xor_vectors(message_bits, G_S)  # XOR the message with G(S) to get the output
        Y = self.additional_functions.xor_vectors(state_bits, message_bits)  # XOR the state with the message to get the updated state
        return Y, O  # Return the updated state and the output
