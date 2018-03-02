# This script picks up hmac hash using server time latency when comparing strings

from cryptography.hmac_service import *
import time

NUMBER_OF_BITS_TO_PICK_UP = 160


def main():
    str_to_send = "Hello"  # first 10 picked up bits are 1111010011
    result = pick_up_hash(str_to_send)
    print(result)

    print(check_hmac_message((str_to_send, result)))


def pick_up_hash(str_to_send):
    hash_to_pickup = _initial_hmac_hash()  # initial hash (all zeroes)
    # start to pick up hash
    for i in range(NUMBER_OF_BITS_TO_PICK_UP):
        first_hash_time = check_hmac_time((str_to_send, hash_to_pickup))

        hash_to_pickup[i] = "1"
        second_hash_time = check_hmac_time((str_to_send, hash_to_pickup))

        # zero was right
        if first_hash_time > second_hash_time:
            hash_to_pickup[i] = "0"

        print("BIT have been picked up! " + str((i + 1)))

    return hash_to_pickup


def check_hmac_time(incoming_message):
    start = time.time()
    check_hmac_message(incoming_message)
    end = time.time()

    return end - start


def _initial_hmac_hash():
    result = []
    for i in range(160):
        result.append("0")

    return result


main()
