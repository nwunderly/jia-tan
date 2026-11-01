#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <fmt/format.h>

constexpr size_t ED448_KEY_LEN = 57;

// real public key
const uint8_t jia_pub[ED448_KEY_LEN] = {
    0x0a, 0x31, 0xfd, 0x3b, 0x2f, 0x1f, 0xc6, 0x92,
    0x92, 0x68, 0x32, 0x52, 0xc8, 0xc1, 0xac, 0x28,
    0x34, 0xd1, 0xf2, 0xc9, 0x75, 0xc4, 0x76, 0x5e,
    0xb1, 0xf6, 0x88, 0x58, 0x88, 0x93, 0x3e, 0x48,
    0x10, 0x0c, 0xb0, 0x6c, 0x3a, 0xbe, 0x14, 0xee,
    0x89, 0x55, 0xd2, 0x45, 0x00, 0xc7, 0x7f, 0x6e,
    0x20, 0xd3, 0x2c, 0x60, 0x2b, 0x2c, 0x6d, 0x31,
    0x00,
};

// public key for private key = {0,...,0} (for testing)
// uint8_t jia_pub[ED448_KEY_LEN] = {
//     0x5B, 0x3A, 0xFE, 0x03, 0x87, 0x8A, 0x49, 0xB2,
//     0x82, 0x32, 0xD4, 0xF1, 0xA4, 0x42, 0xAE, 0xBD,
//     0xE1, 0x09, 0xF8, 0x07, 0xAC, 0xEF, 0x7D, 0xFD,
//     0x9A, 0x7F, 0x65, 0xB9, 0x62, 0xFE, 0x52, 0xD6,
//     0x54, 0x73, 0x12, 0xCA, 0xCE, 0xCF, 0xF0, 0x43,
//     0x37, 0x50, 0x8F, 0x9D, 0x25, 0x29, 0xA8, 0xF1,
//     0x66, 0x91, 0x69, 0xB2, 0x1C, 0x32, 0xC4, 0x80,
//     0x00
// };

bool pubkey_matches(const EVP_PKEY *a, const EVP_PKEY *b) {
    // Keys must be the same algorithm type
    if (EVP_PKEY_get_base_id(a) != EVP_PKEY_get_base_id(b))
        return false;

    // 1 = equal, 0 = different, <0 = error
    int ret = EVP_PKEY_eq(a, b);
    if (ret < 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    return ret == 1;
}

// void set_priv(uint8_t priv[], int val) {
//     // zero the private key
//     std::memset(priv, 0, ED448_KEY_LEN);

//     // set the value
//     std::memcpy(priv, &val, sizeof(val));

//     std::cout << "priv: ";
//     for (int i = 0; i < ED448_KEY_LEN; ++i) {
//         std::cout << fmt::format("{:02X} ", static_cast<int>(priv[i]));
//     }
//     std::cout << std::endl;
// }

void increment_counter(std::vector<uint64_t> &counter) {
    // increment, starting from the least significant byte
    for (int i = counter.size()-1; i >= 0; --i) {
        counter[i]++;

        // fully incremented when we hit the digit with no overflow
        if (counter[i] != 0) {
            break;
        }
    }
}

std::vector<unsigned char> get_public_key(const EVP_PKEY* pkey) {
    size_t len = 0;
    // first call: query required size
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &len) != 1)
        throw std::runtime_error("EVP_PKEY_get_raw_public_key failed (size query)");

    std::vector<unsigned char> buf(len);
    // second call: fill buffer
    if (EVP_PKEY_get_raw_public_key(pkey, buf.data(), &len) != 1)
        throw std::runtime_error("EVP_PKEY_get_raw_public_key failed (fill)");
    buf.resize(len);
    return buf;
}

std::vector<uint64_t> run(int worker_id, int worker_count, int start_point) {
    int increment = worker_count;
    // int val = start_point; // we're just working with priv now
    uint64_t loop_counter = 0;
    auto try_count = std::vector<uint64_t>(100); // basically a stupidly large uint
    int priv_index = 0;

    uint8_t priv[ED448_KEY_LEN] = {};
    // uint8_t pub[ED448_KEY_LEN];
    size_t  pub_len = 0;

    // EVP_PKEY from jia pubkey
    EVP_PKEY *jia_pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED448,
        nullptr,
        jia_pub,
        ED448_KEY_LEN
    );

    EVP_PKEY *pkey;

    while (true) {
        increment_counter(try_count);
        loop_counter++;
        // set_priv(priv, val);

        if (loop_counter % 10000 == 0) {
            std::cout << "count: " << loop_counter << "\n";
        }

        // build EVP_PKEY from raw private key seed
        pkey = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED448, // key type
            nullptr, // libctx
            priv, // key bytes
            ED448_KEY_LEN
        );
        if (!pkey) {
            std::cout << "Error loading private key\n";
            return std::vector<uint64_t>();
        }

        // (public key already exists inside the EVP_PKEY)

        // // sanity check it's actually Ed448
        // if (EVP_PKEY_base_id(pkey) != EVP_PKEY_ED448) {
        //     std::cerr << "Loaded key is not Ed448\n";
        //     EVP_PKEY_free(pkey);
        //     return 1;
        // }

        // WE FOUND IT
        if (pubkey_matches(pkey, jia_pkey)) {
            std::cout << "FOUND IT\n";
            break;
        
        // base case: increment key and continue
        } else {
            // Increment, starting from the least significant byte
            for (int i = ED448_KEY_LEN-1; i >= 0; --i) {
                priv[i]++;
                // Fully incremented when we hit the digit with no overflow
                if (priv[i] != 0) {
                    break;
                }
            }
            continue;
        }
    }

    // write public key to PEM file
    BIO* out = BIO_new_file("ed448_public.pem", "w");
    if (!out) throw std::runtime_error("Cannot create public key file");
    if (PEM_write_bio_PUBKEY(out, pkey) != 1) {
        ERR_print_errors_fp(stderr);
        BIO_free(out);
        EVP_PKEY_free(pkey);
        return try_count;
    }

    // print public key bytes
    std::vector<uint8_t> pub_vec = get_public_key(pkey);
    std::cout << "Key bytes:";
    for (int i = 0; i < ED448_KEY_LEN; ++i)
    {
        std::cout << fmt::format(" 0x{:02X},", static_cast<int>(pub_vec[i]));
    }
    std::cout << std::endl;

    BIO_free(out);
    EVP_PKEY_free(pkey);

    std::cout << "Public key written to ed448_public.pem\n";

    return try_count;
}

std::string uint64_vec_to_dec(const std::vector<uint64_t>& v_in) {
    if (v_in.empty()) return "0";

    // work on a mutable copy
    auto v = v_in;
    std::string digits;

    // optional: strip leading zero limbs
    while (v.size() > 1 && v.front() == 0) v.erase(v.begin());

    while (v.size() > 1 || v[0] != 0) {
        // Divide the whole vector by 10, collect remainder
        uint8_t rem = 0;
        for (size_t i = 0; i < v.size(); ++i) {
            // (rem << 64) + v[i]  divided by 10
            // use __uint128_t (GCC/Clang) or a 64-bit safe split:
            uint8_t hi = rem;                     // previous remainder (0..9)
            uint8_t lo = v[i];
            // value = hi * 2^64 + lo  (hi is at most 9, so this fits in __uint128_t)
            __uint128_t cur = static_cast<__uint128_t>(hi) << 64 | lo;
            v[i]   = static_cast<uint8_t>(cur / 10);
            rem    = static_cast<uint8_t>(cur % 10);
        }
        digits.push_back(char('0' + rem));
    }

    std::reverse(digits.begin(), digits.end());
    return digits;
}

int main(int argc, char *argv[]) {
    std::vector<std::string> args(argv + 1, argv + argc);

    std::cout << "argc: " << argc << "\n";
    std::cout << "args: " << args.size() << "\n";
    for (std::string a : args) {
        std::cout << a << " ";
    }
    std::cout << "\n";

    int num_workers = 1;
    if (args.size() >= 1) {
        num_workers = std::stoi(args[0]);
    }
    std::cout << "num_workers: " << num_workers << "\n";

    int start_point = 0;
    if (args.size() >= 2) {
        start_point = std::stoi(args[1]);
    }
    std::cout << "start_point: " << start_point << "\n";

    std::vector<uint64_t> tries = run(0, 1, start_point);

    std::cout << "Done. Took " << uint64_vec_to_dec(tries) << " tries.\n";

    return 0;
}