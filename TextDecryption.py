class TextDecryption(object):

    # S-Box
    sBox = [
        0x9,        0x4,        0xA,        0xB,
        0xD,        0x1,        0x8,        0x5,
        0x6,        0x2,        0x0,        0x3,
        0xC,        0xE,        0xF,        0x7,
    ]

    # Inverse S-Box
    sBoxI = [
        0xA,        0x5,        0x9,        0xB,
        0x1,        0x7,        0x8,        0xF,
        0x6,        0x0,        0x2,        0x3,
        0xC,        0x4,        0xD,        0xE,
    ]

    def __init__(self, key):
        # Round keys: Key0 = w0 + w1; K1 = w2 + w3; K2 = w4 + w5
        self.pre_round_key, self.round1_key, self.round2_key = self.key_exp(key)
        # print(self.pre_round_key)
        # print(self.round1_key)
        # print(self.round2_key)

    def substitute_word(self, word):

        # Using Sbox table, substitute each nibble in word with another
        return (self.sBox[(word >> 4)] << 4) + self.sBox[word & 0x0F]

    def word_rotate(self, word):

        # It Swap two nibbles in the word since eqv to rotate here
        return ((word & 0x0F) << 4) + ((word & 0xF0) >> 4)

    def key_exp(self, key):

        # Round constants
        Rcon1 = 0x80
        Rcon2 = 0x30

        # Calculate value of each word
        w = [None] * 6 # declaring empty array
        w[0] = (key & 0xFF00) >> 8
        w[1] = key & 0x00FF
        w[2] = w[0] ^ (self.substitute_word(self.word_rotate(w[1])) ^ Rcon1)
        w[3] = w[2] ^ w[1]
        w[4] = w[2] ^ (self.substitute_word(self.word_rotate(w[3])) ^ Rcon2)
        w[5] = w[4] ^ w[3]

        # returns: Tuple containing pre-round, round 1 and round 2 key in order
        return (
            self.int_to_state((w[0] << 8) + w[1]),  # Pre-Round key
            self.int_to_state((w[2] << 8) + w[3]),  # Round 1 key
            self.int_to_state((w[4] << 8) + w[5]),  # Round 2 key
        )

    def gfMult4(self, a, b):
        '''

        Gf multiplication of a and b in GF(2^4) / x^4 + x + 1
        :parameter  a: First number , b: Second number

        '''

        # Initialise
        product = 0

        # Mask unwanted bits
        a = a & 0x0F
        b = b & 0x0F

        # While both multiplicands are non-zero
        while a and b:

            # If LSB of b is 1
            if b & 1:

                # Add current a to product
                product = product ^ a

            # Update a to a * 2
            a = a << 1

            # If a overflows beyond 4th bit
            if a & (1 << 4):

                # XOR with irreducible polynomial with high term eliminated
                a = a ^ 0b10011

            # Update b to b // 2
            b = b >> 1

        # it returns Multiplication of both under GF(2^4)
        return product

    def int_to_state(self, n):
        """
        Convert a 2-byte integer into a 4-element vector (state matrix)
        :param m: integer
        :returns: state corresponding to the integer
        """
        return [n >> 12 & 0xF, (n >> 4) & 0xF, (n >> 8) & 0xF, n & 0xF]

    def state_to_int(self, m):
        """
        Convert a 4-element vector (state matrix) into 2-byte integer
        :param m: state
        :returns: integer corresponding to the state
        """
        return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]

    def add_round_key(self, s1, s2):
        # add key in GF(2^4)
        rk=[i ^ j for i, j in zip(s1, s2)]
        # print("Add Round key")
        # print(rk)


        return [i ^ j for i, j in zip(s1, s2)]

    def sub_nibbles(self, sbox, state):
        substitue_nib= [sbox[nibble] for nibble in state]
        # print("InvSubstitute nibble")
        # print(substitue_nib)
        return [sbox[nibble] for nibble in state]

    def shift_rows(self, state):
       # Shift rows and inverse shift rows of state matrix (same)
       shift_row=[state[0], state[1], state[3], state[2]]
    #    print("InvShift rows:")
    #    print(shift_row)
       return [state[0], state[1], state[3], state[2]]




    def inverse_mix_columns(self, state):
        inv_mix_colm = [
            self.gfMult4(9, state[0]) ^ self.gfMult4(2, state[2]),
            self.gfMult4(9, state[1]) ^ self.gfMult4(2, state[3]),
            self.gfMult4(9, state[2]) ^ self.gfMult4(2, state[0]),
            self.gfMult4(9, state[3]) ^ self.gfMult4(2, state[1]),
        ]
        # print("InvMix columns")
        # print(inv_mix_colm)
        return [
            self.gfMult4(9, state[0]) ^ self.gfMult4(2, state[2]),
            self.gfMult4(9, state[1]) ^ self.gfMult4(2, state[3]),
            self.gfMult4(9, state[2]) ^ self.gfMult4(2, state[0]),
            self.gfMult4(9, state[3]) ^ self.gfMult4(2, state[1]),
        ]



    def decrypt(self, ciphertext):
        # it decrypt cipher text

        # print("After Pre-round transformation:")
        # print("Round key K2:", self.round2_key)
        state = self.add_round_key(self.round2_key, self.int_to_state(ciphertext))

        state = self.sub_nibbles(self.sBoxI, self.shift_rows(state))

        # print("After Round 1 InvAdd round key:", self.round1_key)
        state = self.inverse_mix_columns(self.add_round_key(self.round1_key, state))
        state = self.sub_nibbles(self.sBoxI, self.shift_rows(state))

        # print("Round Key K0:",self.pre_round_key)
        state = self.add_round_key(self.pre_round_key, state)

        return self.state_to_int(state)