import argparse
import time
from multiprocessing import Pool

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey, Ed448PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)

PUBLIC_KEY = bytes.fromhex("""
0a 31 fd 3b 2f 1f c6 92 92 68 32 52 c8 c1 ac 28
34 d1 f2 c9 75 c4 76 5e b1 f6 88 58 88 93 3e 48
10 0c b0 6c 3a be 14 ee 89 55 d2 45 00 c7 7f 6e
20 d3 2c 60 2b 2c 6d 31 00
""".strip().replace("\n", " "))

public_key = Ed448PublicKey.from_public_bytes(PUBLIC_KEY)

# print(PUBLIC_KEY)
# print(len(PUBLIC_KEY))

message = b"balls"

def run(args):
    worker_id, worker_count, start_point = args
    increment = worker_count
    val = start_point
    try_count = 0

    # offset workers so no log overlap (lol)
    time.sleep(worker_id/2)

    print(f"Worker {worker_id} starting at {start_point}")

    while True:
        try_count += 1

        if try_count % 10000 == 0:
            print(f"Worker {worker_id} Test {try_count}: {val}")

        if (val.bit_length() + 7) // 8 > 57:
            print(f"val is somehow too large ({val})")
            break

        # private_key = Ed448PrivateKey.generate()
        b = val.to_bytes(57)
        private_key = Ed448PrivateKey.from_private_bytes(b)
        signature = private_key.sign(message)
        # public_key = private_key.public_key()

        try: # Raises InvalidSignature if verification fails
            public_key.verify(signature, message)
        except:
            # print(f"fail {i}")
            val += increment
            continue

        print(f"HOLY SHIT, WE GOT IT. Took {val} tries.")

        with open("PRIVATE_KEY_RAW", "wb") as fp:
            fp.write(private_key.private_bytes_raw())

        with open("PRIVATE_KEY_BYTES", "w") as fp:
            fp.write(private_key.private_bytes_raw().hex(" "))

        with open("PRIVATE_KEY", "wb") as fp:
            der = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
            fp.write(der)

        return worker_id, try_count


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--start", type=int, default=0)
    args = parser.parse_args()

    wargs = []

    for wid in range(args.workers):
        wargs.append((wid, args.workers, args.start+wid))

    print(f"workers: {wargs}")

    with Pool(args.workers) as pool:
        for finished_worker, result in pool.imap_unordered(run, wargs, chunksize=1):
            break
        print(f"Worker {finished_worker} finished after {result} tries.")
        pool.terminate()

    print("Done.")
