from S3C21 import MT19937
from random import randint
from time import time

# This is to fake the current time and avoid waiting with a sleep()
current_time = int(time())


def routine_rng():
    """Performs the operations specified in the challenge and returns the first result of the
    newly created MT19937 rng.
    """
    global current_time
    current_time += randint(40, 1000)

    seed = current_time
    rng = MT19937(seed)

    current_time += randint(40, 1000)
    return seed, rng.extract_number()


def crack_mt19937_seed(rng_output):
    """Finds the seed that was used to get rng_output as the first output of an MT19937 rng.
    The approach used is to try the most recent timestamps as seeds until the
    first output of the newly created MT19937 matches rng_output.
    """
    global current_time

    # Start from the current timestamp plus one second, so that we can still find the seed even when the
    # timestamp was not increased (or the program ran fast enough to get the answer in the same timestamp)
    guessed_seed = current_time + 1
    rng = MT19937(guessed_seed)

    # Decrease the Unix timestamp by 1 second every time until we find the same output
    while rng.extract_number() != rng_output:
        guessed_seed -= 1
        rng = MT19937(guessed_seed)

    # If the output of a MT19937 with our guessed seed was the same as rng_output, then
    # it means that the seed we guessed was really equal to the original one.
    return guessed_seed


def main():
    real_seed, rng_output = routine_rng()
    assert real_seed == crack_mt19937_seed(rng_output)


if __name__ == '__main__':
    main()
