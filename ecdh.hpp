#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string>

class ECDH
{
public:
    ECDH();
    ~ECDH();
    void generate_key();
    void compute_key(const EC_POINT *peer_pub_key);

    const EC_POINT *get_public_key();
    unsigned char *get_public_key_str();
    size_t get_public_key_len();
    unsigned char *get_shared_key();
    size_t get_shared_key_len();
    void print_key();

private:
    EVP_PKEY *key;
    unsigned char *publicKey;
    size_t publicKeyLen;
    unsigned char *sharedKey;
    size_t sharedKeyLen;
};
