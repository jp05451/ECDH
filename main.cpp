#include "ecdh.hpp"
#include <iostream>

using namespace std;

int main()
{
    ECDH alice;
    ECDH bob;

    alice.generate_key();
    bob.generate_key();

    const EC_POINT *alice_pub_key = alice.get_public_key();
    const EC_POINT *bob_pub_key = bob.get_public_key();

    alice.compute_key(bob_pub_key);
    bob.compute_key(alice_pub_key);

    unsigned char *alice_shared_key = alice.get_shared_key();
    unsigned char *bob_shared_key = bob.get_shared_key();

    // 比較共享金鑰是否相同
    if (memcmp(alice_shared_key, bob_shared_key, alice.get_shared_key_len()) == 0)
    {
        cout << "Shared key is the same." << endl;
    }
    else
    {
        cout << "Shared key is different." << endl;
    }

    // 顯示金鑰資訊
    alice.print_key();
    bob.print_key();

    return 0;
}