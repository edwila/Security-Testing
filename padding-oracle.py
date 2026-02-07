#!/usr/bin/env python3
import json
import sys
import time
from typing import Dict, List
import requests
# Create one session for each oracle request to share. This allows the
# underlying connection to be re-used, which speeds up subsequent requests!
s = requests.session()
def oracle(url: str, messages: List[bytes]) -> List[Dict[str, str]]:
    while True:
        try:
            r = s.post(url, data={"message": [m.hex() for m in messages]})
            r.raise_for_status()
            return r.json()
        # Under heavy server load, your request might time out. If this happens,
        # the function will automatically retry in 10 seconds for you.
        except requests.exceptions.RequestException as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\nRetrying in 10 seconds...\n")
            time.sleep(10)
            continue
        except json.JSONDecodeError as e:
            sys.stderr.write("It's possible that the oracle server is overloaded right now, or that provided URL is wrong.\n")
            sys.stderr.write("If this keeps happening, check the URL. Perhaps your uniqname is not set.\n")
            sys.stderr.write("Retrying in 10 seconds...\n\n")
            time.sleep(10)
            continue
def decrypt_block(oracle_url: str, prev_block: bytes, curr_block: bytes) -> bytes:
    block_size = 16
    intermediate = bytearray(block_size)
    
    for pad_val in range(1, block_size + 1):
        fake_prev = bytearray(block_size)
        
        for i in range(1, pad_val):
            fake_prev[block_size - i] = intermediate[block_size - i] ^ pad_val
        
        found = False
        for guess in range(256):
            fake_prev[block_size - pad_val] = guess
            test_ciphertext = bytes(fake_prev) + curr_block
            result = oracle(oracle_url, [test_ciphertext])[0]
            
            if result["status"] not in ("invalid_padding", "invalid_length", "invalid_iv"):
                if pad_val == 1:
                    temp_fake = bytearray(fake_prev)
                    temp_fake[block_size - 2] ^= 1
                    temp_test = bytes(temp_fake) + curr_block
                    temp_result = oracle(oracle_url, [temp_test])[0]
                    if temp_result["status"] == "invalid_padding":
                        continue
                
                intermediate[block_size - pad_val] = pad_val ^ guess
                found = True
                break
        
        if not found:
            raise Exception(f"Decrypting failed for some reason on block {block_size - pad_val}")
    
    return bytes([intermediate[i] ^ prev_block[i] for i in range(block_size)])
def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} ORACLE_URL CIPHERTEXT_HEX", file=sys.stderr)
        sys.exit(-1)
    oracle_url, message = sys.argv[1], bytes.fromhex(sys.argv[2])
    if oracle(oracle_url, [message])[0]["status"] != "valid":
        print("Message invalid", file=sys.stderr)
    block_size = 16
    blocks = [message[i:i+block_size] for i in range(0, len(message), block_size)]
    
    plaintext_blocks = []
    for i in range(1, len(blocks)):
        prev_block = blocks[i - 1]
        curr_block = blocks[i]
        decrypted_block = decrypt_block(oracle_url, prev_block, curr_block)
        plaintext_blocks.append(decrypted_block)
    
    full_plaintext = b''.join(plaintext_blocks)
    
    # remove padding and MAC
    pad_len = full_plaintext[-1]
    full_plaintext = full_plaintext[:-pad_len]
    msg = full_plaintext[:-32]
    
    print(msg.decode("utf-8"))
if __name__ == '__main__':
    main()
