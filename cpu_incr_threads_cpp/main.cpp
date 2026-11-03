#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <mutex>
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
    // keys must be the same algorithm type
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

void set_priv(uint8_t priv[], int val) {
    // zero the private key
    std::memset(priv, 0, ED448_KEY_LEN);

    // set the value
    std::memcpy(priv, &val, sizeof(val));

    std::cout << "priv: ";
    for (int i = 0; i < ED448_KEY_LEN; ++i) {
        std::cout << fmt::format("{:02X} ", static_cast<int>(priv[i]));
    }
    std::cout << std::endl;
}

void increment_counter(std::vector<uint8_t>& v) {
    for (size_t i = 0; i < v.size(); ++i) {
        v[i]++;

        // stop when there is no overflow
        if (v[i] != 0) {
            break;
        }
    }
}

std::vector<unsigned char> get_private_key(const EVP_PKEY* pkey) {
    size_t len = 0;
    // first call: query required size
    if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &len) != 1)
        throw std::runtime_error("EVP_PKEY_get_raw_private_key failed (size query)");

    std::vector<unsigned char> buf(len);
    // second call: fill buffer
    if (EVP_PKEY_get_raw_private_key(pkey, buf.data(), &len) != 1)
        throw std::runtime_error("EVP_PKEY_get_raw_private_key failed (fill)");

    buf.resize(len);
    return buf;
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

void dump_private_key(const EVP_PKEY* pkey, const std::string& filename) {
    // write private key to PEM file
    BIO* out = BIO_new_file(filename.c_str(), "w");
    if (!out)
        throw std::runtime_error("Cannot create private key file");

    if (PEM_write_bio_PrivateKey(out, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(out);
        throw std::runtime_error("Failed to write private key");
    }

    BIO_free(out);

    // print private key bytes
    std::vector<unsigned char> priv_vec = get_private_key(pkey);
    std::cout << "Private key bytes:";
    for (const auto byte : priv_vec) {
        std::cout << fmt::format(" 0x{:02X},", static_cast<int>(byte));
    }
    std::cout << std::endl;
}

void dump_public_key(const EVP_PKEY* pkey, const std::string& filename) {
    // write public key bytes to PEM file
    BIO* out = BIO_new_file(filename.c_str(), "w");
    if (!out)
        throw std::runtime_error("Cannot create public key file");

    if (PEM_write_bio_PUBKEY(out, pkey) != 1) {
        BIO_free(out);
        throw std::runtime_error("Failed to write public key");
    }

    BIO_free(out);

    // print public key bytes
    std::vector<unsigned char> pub_vec = get_public_key(pkey);
    std::cout << "Public key bytes:";
    for (const auto byte : pub_vec) {
        std::cout << fmt::format(" 0x{:02X},", static_cast<int>(byte));
    }
    std::cout << std::endl;
}

std::string uint8_t_vec_to_dec(const std::vector<uint8_t>& v_in) {
    if (v_in.empty()) return "0";

    auto v = v_in;
    std::string digits;

    while (true) {
        uint16_t rem = 0;

        for (size_t i = v.size(); i-- > 0;) {
            uint16_t cur = rem * 256 + v[i];
            v[i] = static_cast<uint8_t>(cur / 10);
            rem = cur % 10;
        }

        digits.push_back('0' + rem);

        // remove leading zero bytes (most significant end)
        while (v.size() > 1 && v.back() == 0) {
            v.pop_back();
        }

        if (v.size() == 1 && v[0] == 0) {
            break;
        }
    }

    std::reverse(digits.begin(), digits.end());
    return digits;
}

std::vector<uint8_t> run(
    int worker_id,
    int worker_count,
    int start_point,
    std::atomic<bool>& stop
) {
    int increment = worker_count;
    uint64_t loop_counter = 0;
    auto try_count = std::vector<uint8_t>(ED448_KEY_LEN+1, 0); // basically a stupidly large uint
    int priv_index = 0;
    bool found = false;

    auto priv_vec = std::vector<uint8_t>(ED448_KEY_LEN, 0);
    // uint8_t priv[ED448_KEY_LEN] = {};
    uint8_t *priv = priv_vec.data();
    // uint8_t pub[ED448_KEY_LEN];
    size_t pub_len = 0;

    // hacky way to dodge logging race conditions
    std::this_thread::sleep_for(std::chrono::milliseconds(100+100*worker_id));
    std::cout << "worker: " << worker_id << " start_point: " << start_point << "\n";

    // set priv = start_point
    set_priv(priv, start_point);

    // EVP_PKEY from jia pubkey
    EVP_PKEY *jia_pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED448,
        nullptr,
        jia_pub,
        ED448_KEY_LEN
    );

    EVP_PKEY *pkey;

    while (!stop.load(std::memory_order_relaxed)) {
        increment_counter(try_count);
        loop_counter++;

        if (loop_counter % 10000 == 0) {
            std::string priv_val_str = uint8_t_vec_to_dec(priv_vec);
            std::cout << "worker: " << worker_id
                << " count: " << loop_counter
                << " priv: " << priv_val_str
                << std::endl;
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
            stop.store(true, std::memory_order_relaxed);
            return {};
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
            stop.store(true, std::memory_order_relaxed);
            found = true;
            break;
        }
        
        // base case: increment key and continue
        else {
            increment_counter(priv_vec);
            continue;
        }
    }

    // this thread was signaled to stop
    if (!found) {
        EVP_PKEY_free(pkey);
        return {};
    }

    // we found the key
    else {
        dump_private_key(pkey, "ed448_private.pem");
        dump_public_key(pkey, "ed448_public.pem");
        EVP_PKEY_free(pkey);
        return try_count;
    }
}

std::vector<uint8_t> run_threads(int worker_count, int start_point) {
    std::atomic<bool> stop{false};

    std::mutex mtx;
    std::vector<uint8_t> first_result;
    int finished_worker = -1;

    std::vector<std::thread> threads;
    threads.reserve(worker_count);

    for (int wid = 0; wid < worker_count; ++wid) {
        threads.emplace_back(
            [&mtx, &stop, &first_result, &finished_worker,
             wid, worker_count, start_point]() {

                auto result = run(
                    wid,
                    worker_count,
                    start_point + wid,
                    stop
                );

                // only one worker will have the result
                if (!result.empty()) {
                    std::lock_guard lock(mtx);

                    if (finished_worker == -1) {
                        finished_worker = wid;
                        first_result = std::move(result);
                    }
                }
            }
        );
    }

    // wait for all workers to close
    for (auto& t : threads) {
        t.join();
    }

    std::cout << "First successful worker: "
              << finished_worker << "\n";

    return first_result;
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

    // std::vector<uint8_t> tries = run(0, 1, start_point);
    std::vector<uint8_t> tries = run_threads(num_workers, start_point);

    std::cout << "Done. Took " << uint8_t_vec_to_dec(tries) << " tries.\n";

    return 0;
}