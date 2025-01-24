#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

class ECDH
{
public:
    ECDH();
    ~ECDH();
    void generate_key();
    void compute_key(const EC_POINT *peer_pub_key);

    EC_POINT *get_public_key();
    unsigned char *get_shared_key();
    size_t get_shared_key_len();
    void print_key();

private:
    EC_KEY *key;
    unsigned char *sharedKey;
    size_t sharedKeyLen;
};
