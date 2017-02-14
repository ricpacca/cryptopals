from S3C21 import MT19937
from random import randint


def get_bit(number, position):
    """Returns the bit at the given position of the given number. The position
    is counted starting from the left in the binary representation (from the most
    significant to the least significant bit).
    """
    if position < 0 or position > 31:
        return 0
    return (number >> (31 - position)) & 1


def set_bit_to_one(number, position):
    """Sets the bit at the given position of the given number to 1.The position
    is counted starting from the left in the binary representation (from the most
    significant to the least significant bit).
    """
    return number | (1 << (31 - position))


def undo_right_shift_xor(result, shift_len):
    """When the right shift and then XOR are done, the first "shift_len" bits of the result
    (starting from the left) are the same as the original value before the operation (try
    it on paper, it is simply because when we shift the input to the right its first bits
    will be zeros, and when we XOR something against zeros, that something does not change).

    The following bits will instead be equal to the XOR of the original bit at their same
    position and the original bit that was "shift_len" positions behind. It will be easy
    then to recover the original bit at their position by simply XORing the resulting bit
    with the original bit "shift_len" positions behind (and we already have that bit because
    we started this process from the left).
    """
    original = 0
    for i in range(32):
        next_bit = get_bit(result, i) ^ get_bit(original, i - shift_len)
        if next_bit == 1:
            original = set_bit_to_one(original, i)

    return original


def undo_left_shift_xor_and(result, shift_len, andd):
    """When the left shift, then XOR and then the AND are done, we can reverse the process
    bit by bit by redoing the AND between the un-shifted resulting value and the and'd value
    and then by XORing with the corresponding bit of the given result.
    Sounds like magic, but try it on paper and you'll see that it works.
    This time the process is doing starting from the right and each bit is AND'd with the bit
    shift_len positions above.
    """
    original = 0
    for i in range(32):
        next_bit = get_bit(result, 31 - i) ^ \
                   (get_bit(original, 31 - (i - shift_len)) &
                    get_bit(andd, 31 - i))

        if next_bit == 1:
            original = set_bit_to_one(original, 31 - i)

    return original


def untemper(y):
    """Reverts the operations done in the "tampering" process when the function extract_number() of
    the MT19937 generator is called, and returns the initial value state of the generator corresponding
    to its current index.
    """
    y = undo_right_shift_xor(y, MT19937.L)
    y = undo_left_shift_xor_and(y, MT19937.T, MT19937.C)
    y = undo_left_shift_xor_and(y, MT19937.S, MT19937.B)
    y = undo_right_shift_xor(y, MT19937.U)
    return y


def get_cloned_rng(original_rng):
    """Taps the given rng for 624 outputs, untempers each of them to recreate the state of the generator,
    and splices that state into a new "cloned" instance of the MT19937 generator.
    """
    mt = []

    # Recreate the state mt of original_rng
    for i in range(MT19937.N):
        mt.append(untemper(original_rng.extract_number()))

    # Create a new generator and set it to have the same state
    cloned_rng = MT19937(0)
    cloned_rng.mt = mt

    return cloned_rng


def main():
    seed = randint(0, 2**32 - 1)
    rng = MT19937(seed)
    cloned_rng = get_cloned_rng(rng)

    # Check that the two PRNGs produce the same output now
    for i in range(1000):
        assert rng.extract_number() == cloned_rng.extract_number()


if __name__ == '__main__':
    main()
