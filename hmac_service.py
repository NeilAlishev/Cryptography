# TODO: implement hmac algorithm manually
import hmac
import hashlib
import time

SECRET_SHARED_KEY = b"12345"


def generate_hmac(original_msg, secret_key):
    return hmac.new(secret_key, original_msg.encode(), hashlib.sha1).digest()


# returns tuple consisting of the message and the hmac hash of the message
# ready to be sent over the insecure medium
def generate_final_message(original_msg, secret_key):
    return original_msg, generate_hmac(original_msg, secret_key)


# Мы хотим подделывать любое сообщение, для этого мы должны подделать хэш, чтобы
# он соответствовал тому хэшу, который будет получаться на сервере при hmac(key, original_msg)
# при этом мы не узнаем ключ, но сможем посылать на сервер любое сообщение как
# авторизованный отправитель.

# this function checks if hmac message was actually untouched and came
# from the authorized sender (the one who has SECRET_SHARED_KEY)
# incoming message is a tuple(msg, hmac_hash)
# returns true if message wasn't modified and was sent from authorized sender
def check_hmac_message(incoming_message):
    generated_hmac = generate_hmac(incoming_message[0], SECRET_SHARED_KEY)

    hmac1_bits = _convert_to_bits_array(generated_hmac)
    # hmac2_bits = _convert_to_bits_array(incoming_message[1])
    hmac2_bits = incoming_message[1]  # don't covert, already in the bits array format

    return _very_unsafe_compare(hmac1_bits, hmac2_bits)


def _very_unsafe_compare(hmac1_bits, hmac2_bits):
    for i in range(160):
        if hmac1_bits[i] != hmac2_bits[i]:
            return False

        time.sleep(0.05)

    return True


def _convert_to_bits_array(hmac):
    result = []
    for byte in hmac:
        byte_str = '{0:08b}'.format(byte)
        bits_arr = list(byte_str)
        for bit in bits_arr:
            result.append(bit)

    return result

#
# def main():
#     message = generate_final_message("Hello", SECRET_SHARED_KEY)
#     print(_convert_to_bits_array(message[1]))
#
#
# main()
