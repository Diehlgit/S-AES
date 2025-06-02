#Add Round key
# This operation involves XORing a 16-bit round key onto the 16-bit state.
# The state is shown here always as 4×4-table, each cell contains a nibble and
# the first column is the first byte and the second column is the second byte.


#Substitute Nibbles
# Substitute nibbles Instead of dividing the block into a four by four array of bytes, S-AES
# divides it into a two by two array of “nibbles”, which are four bits long.
# Applies a 4-bit S-box to the 16-bit state. The S-box is a lookup table that replaces
# each 4-bit input with a corresponding 4-bit output. 


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