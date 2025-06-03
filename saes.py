#Auxiliary functions to process strings input into the required formats
# input : ASCII encoded str, two chars lenght

# From the input string returns the 16bit int
def string_to_int(s: str) -> int:
    if len(s) != 2:
        raise ValueError("Input string must be exactly 2 characters long")
    return (ord(s[0]) << 8) | ord(s[1])

# From a 16bit int block returns the matrix of 2x2 nibbles 
def int_to_state(block: int) -> list[list[int]]:
    return [
        [(block >> 12) & 0xF, (block >> 4) & 0xF],
        [(block >> 8) & 0xF, block & 0xF]
    ]

# From a matrix of 2x2 nibbles returns a 16bit int
def state_to_int(state: list[list[int]]) -> int:
    return (
        ((state[0][0] & 0xF) << 12) |
        ((state[1][0] & 0xF) << 8)  |
        ((state[0][1] & 0xF) << 4)  |
        (state[1][1] & 0xF)
    )

#Add Round key
# This operation involves XORing a 16-bit round key onto the 16-bit state.
# The state is shown here always as 4×4-table, each cell contains a nibble and
# the first column is the first byte and the second column is the second byte.

def add_round_key(state: list[list[int]], round_key: list[list[int]]) -> list[list[int]]:
    return [
        [state[0][0] ^ round_key[0][0], state[0][1] ^ round_key[0][1]],
        [state[1][0] ^ round_key[1][0], state[1][1] ^ round_key[1][1]]
    ]

#Substitute Nibbles
# Substitute nibbles Instead of dividing the block into a four by four array of bytes, S-AES
# divides it into a two by two array of “nibbles”, which are four bits long.
# Applies a 4-bit S-box to the 16-bit state. The S-box is a lookup table that replaces
# each 4-bit input with a corresponding 4-bit output. 
sbox = [
    0b1001, 0b0100, 0b1010, 0b1011,
    0b1101, 0b0001, 0b1000, 0b0101,
    0b0110, 0b0010, 0b0000, 0b0011,
    0b1100, 0b1110, 0b1111, 0b0111
]

def substitute_nibbles(state: list[list[int]]) -> list[list[int]]:
    return [
        [sbox[state[0][0]], sbox[state[0][1]]],
        [sbox[state[1][0]], sbox[state[1][1]]]
    ]


#Shift Rows
# Involves exchanging the last two nibbles of the 16-bit state.
# It’s important to note that this operation is self-inverse,
# meaning it can be reversed to decrypt the data. 
#   ShiftRows(DF1A) = DA1F


#Mix Columns
# Applies a matrix operation on the 16-bit state within the Galois field GF(16).


#Expand Key
# Computes round keys for each round.
# It employs a round constant array (Rcon) to generate the necessary keys.  


#G function
# The g function is shown in the next diagram. It is very similar to AES, first rotating the nibbles
# and then putting them through the S-boxes. The main difference is that the round constant is produced using x^(j+2)
# where j is the number of the round of expansion.
# That is, the first time you expand the key you use 
# a round constant of x^3 = 1000 for the first nibble
# and 0000 for the second nibble.
# The second time you use x^4 = 0011 for the first nibble
# and 0000 for the second nibble.