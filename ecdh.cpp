#include "ecdh.hpp"

using namespace std;

// ...existing code...
ECDH::ECDH()
{
    key = nullptr;
    sharedKey = nullptr;
    sharedKeyLen = 0;
}

ECDH::~ECDH()
{
    if (key)
    {
        EC_KEY_free(key);
        key = nullptr;
    }
    if (sharedKey)
    {
        OPENSSL_free(sharedKey);
        sharedKey = nullptr;
    }
}

void ECDH::generate_key()
{
    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    // 產生 EC_KEY
    EC_KEY_generate_key(key);
}

void ECDH::compute_key(const EC_POINT *peer_pub_key)
{
    // 使用 ECDH_compute_key() 計算共享金鑰，存入 sharedKey
    // 更新 sharedKeyLen
    int fieldSize = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    sharedKeyLen = (fieldSize + 7) / 8;
    sharedKey = (unsigned char *)OPENSSL_malloc(sharedKeyLen);
    ECDH_compute_key(sharedKey, sharedKeyLen, peer_pub_key, key, nullptr);
}

EC_POINT *ECDH::get_public_key()
{
    // 傳回本地端公鑰
    return (EC_POINT *)EC_KEY_get0_public_key(key);
}

unsigned char *ECDH::get_shared_key()
{
    // 傳回 sharedKey
    return sharedKey;
}

void ECDH::print_key()
{
    // 顯示金鑰資訊
    // 可使用 BN_bn2hex() 轉換或顯示
    for (size_t i = 0; i < sharedKeyLen; i++)
    {
        printf("%02X", sharedKey[i]);
    }
    printf("\n");
}

size_t ECDH::get_shared_key_len()
{
    // 傳回 sharedKeyLen
    return sharedKeyLen;
}