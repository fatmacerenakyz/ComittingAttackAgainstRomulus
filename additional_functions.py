import os

class AdditionalFunctions:
    def __init__(self):
        self.block_size = 16  # Block size is fixed to 16 bytes (128 bits)
        self.S8 = [
            0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b,
            0x55, 0x75, 0x5a, 0x7a, 0x53, 0x73, 0x5b, 0x7b,
            0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b,
            0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b,
            0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0, 0xe9,
            0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,
            0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9,
            0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9,
            0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d,
            0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d,
            0x62, 0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d,
            0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,
            0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad,
            0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd,
            0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed,
            0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd,
            0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83, 0x39,
            0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
            0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69,
            0x56, 0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79,
            0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab,
            0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb,
            0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3, 0xc3, 0xeb,
            0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,
            0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f,
            0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f,
            0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f,
            0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f,
            0xa2, 0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf,
            0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,
            0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef,
            0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff
        ]
        self.G_s = [
            [0, 1, 0, 0, 0, 0, 0, 0],
            [0, 0, 1, 0, 0, 0, 0, 0],
            [0, 0, 0, 1, 0, 0, 0, 0],
            [0, 0, 0, 0, 1, 0, 0, 0],
            [0, 0, 0, 0, 0, 1, 0, 0],
            [0, 0, 0, 0, 0, 0, 1, 0],
            [0, 0, 0, 0, 0, 0, 0, 1],
            [1, 0, 0, 0, 0, 0, 0, 1]
        ]
        
    # --- Padding utilities ---
    def pad_L(self, data: bytes) -> bytes:
        """
        Pads the input data to ensure its length is a multiple of the block size.
        The padding is done by appending zero bytes until the data length is a multiple of the block size.

        Args:
        - data (bytes): The data to be padded.

        Returns:
        - bytes: The padded data.
        """
        remainder = len(data) % self.block_size  # Calculate the remainder when dividing the data length by block_size
        if remainder == 0:
            return data  # No padding needed if data is already a multiple of block_size
        
        padding_len = self.block_size - remainder  # Calculate the number of bytes to pad
        return data + b'\x00' * padding_len  # Append the necessary number of zero bytes to the data
    
    def unpad_L(self, padded_data: bytes) -> bytes:
        """
        Removes padding from the data that was previously padded using the `pad_L` method.

        Args:
        - padded_data (bytes): The padded data to unpad.

        Returns:
        - bytes: The data after removing the padding.
        """
        padding_len = padded_data[-1]  # The last byte indicates the padding length
        if padding_len == 0 or padding_len > self.block_size:
            return padded_data  # Invalid padding, return data as is
        
        # Check if padding is valid (all padding bytes should be zero)
        if padded_data[-padding_len:-1] != b'\x00' * (padding_len - 1):
            return padded_data  # Invalid padding, return data unchanged
        
        return padded_data[:-padding_len]  # Remove the padding bytes from the end of the data

    # --- Matrix utilities (4x4 byte matrices for SKINNY) ---
    def block_to_matrix(self, block):
        """
        Converts a 16-byte block into a 4x4 matrix.

        Args:
        - block (bytes): The 16-byte block to convert.

        Returns:
        - list of list of int: The 4x4 matrix representation of the block.
        
        Raises:
        - ValueError: If the block size is not 16 bytes.
        """
        if len(block) != 16:
            raise ValueError("Block must be 16 bytes.")
        return [list(block[i*4:(i+1)*4]) for i in range(4)]  # Convert block into 4x4 matrix
    
    def matrix_to_block(self, state):
        """
        Converts a 4x4 matrix back into a 16-byte block.

        Args:
        - state (list of list of int): The 4x4 matrix to convert.

        Returns:
        - list of int: The 16-byte block representation of the matrix.
        """
        return [byte for row in state for byte in row]  # Flatten the 4x4 matrix into a single list of bytes

    def xor_matrices(self, m1, m2):
        """
        Performs an XOR operation between two matrices.

        Args:
        - m1 (list of list of int): The first matrix.
        - m2 (list of list of int): The second matrix.

        Returns:
        - list of list of int: The result of XORing the two matrices element-wise.
        """
        return [[(a ^ b) & 0xFF for a, b in zip(r1, r2)] for r1, r2 in zip(m1, m2)]  # XOR each element of the matrices

    # --- XOR for bits OR bytes ---
    def xor_vectors(self, v1, v2):
        """
        XORs two vectors (either bit vectors or byte vectors).
        Assumes elements are int.

        Args:
        - v1 (list of int): The first vector.
        - v2 (list of int): The second vector.

        Returns:
        - list of int: The result of XORing the two vectors element-wise.
        """
        return [(a ^ b) for a, b in zip(v1, v2)]  # XOR each corresponding element of the two vectors

    # --- Conversion helpers ---
    def bytes_to_bits(self, byte_list):
        """
        Converts a list of bytes to a list of bits.

        Args:
        - byte_list (list of int): The list of bytes to convert.

        Returns:
        - list of int: The list of bits representing the input bytes.
        """
        return [(byte >> i) & 1 for byte in byte_list for i in reversed(range(8))]  # Convert each byte to 8 bits
    
    def bits_to_bytes(self, bit_list):
        """
        Converts a list of bits to a list of bytes.

        Args:
        - bit_list (list of int): The list of bits to convert.

        Returns:
        - list of int: The list of bytes representing the input bits.
        """
        return [int("".join(str(b) for b in bit_list[i:i + 8]), 2) for i in range(0, len(bit_list), 8)]  # Convert bits to bytes

    # --- Input parsing ---
    def divide_input_into_blocks(self, input_data):
        """
        Divides input data into blocks of the specified block size.

        Args:
        - input_data (bytes): The input data to divide.

        Returns:
        - list of bytes: A list of blocks of the input data.
        """
        return [input_data[i:i + self.block_size] for i in range(0, len(input_data), self.block_size)]  # Divide data into blocks

    def tweakey_to_matrices(self, tweakey):
        """
        Converts a 48-byte tweakey into three 4x4 matrices.

        Args:
        - tweakey (bytes): The 48-byte tweakey to convert.

        Returns:
        - list of list of list of int: A list containing three 4x4 matrices representing the tweakey.
        
        Raises:
        - ValueError: If the tweakey is not exactly 48 bytes long.
        """
        if len(tweakey) != 48:
            raise ValueError("Tweakey must be 48 bytes.")
        blocks = [tweakey[i:i + 16] for i in range(0, len(tweakey), 16)]  # Split tweakey into 16-byte blocks
        return [self.block_to_matrix(block) for block in blocks]  # Convert each block into a 4x4 matrix

    def validate_key_nonce(self, key: bytes, nonce: bytes):
        """
        Validates the key and nonce lengths.

        Args:
        - key (bytes): The key to validate (must be 48 bytes).
        - nonce (bytes): The nonce to validate (must be 16 bytes).

        Raises:
        - ValueError: If the key or nonce lengths are incorrect.
        """
        if not isinstance(key, bytes) or len(key) != 48:
            raise ValueError("Key must be exactly 48 bytes long (TK1 || TK2 || TK3).")
        if not isinstance(nonce, bytes) or len(nonce) != 16:
            raise ValueError("Nonce must be exactly 16 bytes long (128 bits).")

    def random_bitstring(self, n_bytes):
        """
        Generates a random bitstring of the specified length.

        Args:
        - n_bytes (int): The number of bytes for the random bitstring.

        Returns:
        - list of int: A list of random bits (0 or 1).
        """
        return list(os.urandom(n_bytes))  # Generate a random byte list and return it as a list of bits
