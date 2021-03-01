#include <iostream>

#include "../crypto/crypto.h"

class person
{
public:
    person()
    {
        chacha20 = chacha20_poly1305_key();
        firesaber = firesaber_kem();

        ss = 0;
        k = 0;
    }

    ~person()
    {
        delete chacha20;
        delete firesaber;

        if (ss) free(ss);
        if (k) free(k);
    }

    /// <summary>
    /// Generates a Public and Private Key for the key exchange
    /// </summary>
    /// <returns>The Public Key</returns>
    unsigned char* generate_key() // HINT: free(output)
    {
        k = (unsigned char*)malloc(firesaber->secret_key_len);
        unsigned char* pk = (unsigned char*)malloc(firesaber->public_key_len);
        firesaber->GenerateKey(pk, k);
        return pk;
    }

    /// <summary>
    /// Encapsulated the Generated Public Key for the key exchange
    /// </summary>
    /// <param name="pk">Public Key</param>
    /// <returns>Ciphertext to send to other client for the key exchange otherwise returns 0 if error</returns>
    unsigned char* encapsulate_pk(unsigned char* pk) // HINT: free(output)
    {
        unsigned char* ct = (unsigned char*)malloc(firesaber->cipher_text_len);
        ss = (unsigned char*)malloc(firesaber->shared_secret_len);
        if (!firesaber->Encapsulate(ct, ss, pk)) { free(ct); return 0; }
        return ct;
    }

    /// <summary>
    /// Decapsulates the Ciphertext to complete the key exchange
    /// </summary>
    /// <param name="ct">Ciphertext</param>
    /// <returns>If Decapsulate is Completed otherwise returns 0 if error</returns>
    bool decapsulate_ct(unsigned char* ct)
    {
        ss = (unsigned char*)malloc(firesaber->shared_secret_len);
        if (!firesaber->Decapsulate(ss, ct, k)) return false;
        return true;
    }

    /// <summary>
    /// Encrypts a message after a key exchange has happened
    /// </summary>
    /// <param name="msg">Message to encrypt</param>
    /// <param name="size">Size of Message</param>
    /// <param name="out_nonce">Output Nonce</param>
    /// <param name="out_size">Output Size</param>
    /// <returns>Returns Encrypted Message otherwise returns 0 if error</returns>
    unsigned char* encrypt_message(unsigned char* msg, unsigned int size, unsigned char** out_nonce, unsigned int* out_size) // HINT: free(output)
    {
        if (!ss) return 0;
        *out_nonce = (unsigned char*)malloc(chacha20->nonce_size);
        rand_bytes(*out_nonce, (unsigned long long)chacha20->nonce_size);
        unsigned char* enc_msg = (unsigned char*)malloc(size + chacha20->cipher_text_extra_size);
        if (!chacha20->Encrypt(msg, size, ss, *out_nonce, enc_msg)) { free(out_nonce); free(enc_msg); return 0; };
        *out_size = size + chacha20->cipher_text_extra_size;
        return enc_msg;
    }

    /// <summary>
    /// Decrypts a message after a key exchange has happened
    /// </summary>
    /// <param name="msg">Encrypted Message</param>
    /// <param name="size">Size of Encrypted Message</param>
    /// <param name="nonce">Nonce</param>
    /// <returns>Returns Decrypted Message otherwise returns 0 if error</returns>
    unsigned char* decrypt_message(unsigned char* msg, unsigned int size, unsigned char* nonce) // HINT: free(output)
    {
        if (!ss) return 0;
        unsigned char* dec_msg = (unsigned char*)malloc(size - chacha20->cipher_text_extra_size);
        if (!chacha20->Decrypt(msg, size, ss, nonce, dec_msg)) { free(dec_msg); return 0; };
        return dec_msg;
    }

private:
    sync_key_t* chacha20;
    kem_t* firesaber;

    unsigned char* ss;
    unsigned char* k;
};

/// <summary>
/// Alice and Bob Key Exchange
/// </summary>
/// <param name="alice">Alice's client</param>
/// <param name="bob">Bob's client</param>
/// <returns>returns true if successful</returns>
bool alice_bob_key_exchange(person* alice, person* bob)
{
    /*
    * KEY EXCHANGE
    * 
    * Alice generates a secret key and a public key
    * Alice's public key -> Bob
    * Bob creates Ciphertext and Shared Secret Key based on Alice's public key
    * Bob ciphertext -> Alice
    * Alice creates a shared secret from Bob's ciphertext
    */

    unsigned char* pk = alice->generate_key();
    if (!pk) return false;

    unsigned char* ct = bob->encapsulate_pk(pk);
    free(pk);
    if (!ct) return false;

    if (!alice->decapsulate_ct(ct)) return 0;
    free(ct);

    return true;
}

/// <summary>
/// Alice and Bob Send Message between eachother
/// </summary>
/// <param name="alice">Alice's client</param>
/// <param name="bob">Bob's client</param>
/// <returns>returns true if successful</returns>
bool alice_bob_send_message(person* alice, person* bob)
{
    unsigned char* msg = (unsigned char*)"test";

    unsigned char* nonce;
    unsigned int size;
    unsigned char* encrypted_message = alice->encrypt_message(msg, strlen((char*)msg) + 1, &nonce, &size);
    if (!encrypted_message) return false;

    std::cout << "encrypted_message" << encrypted_message << std::endl;
    unsigned char* decrypted_message = bob->decrypt_message(encrypted_message, size, nonce);
    free(encrypted_message);
    if (!decrypted_message) return false;

    std::cout << "decrypted_message: " << decrypted_message << std::endl;
    free(decrypted_message);
    return true;
}

int main()
{
    init_rand_state();

    unsigned char* seed = (unsigned char*)malloc(32);
    for (int i = 0; i < 32; i++)
        seed[i] = i;

    seed_rand(seed);
    get_rand_seed(seed);
    free(seed);

    person* alice = new person();
    person* bob = new person();

    if (!alice_bob_key_exchange(alice, bob)) return 0;

    if (!alice_bob_send_message(alice, bob)) return 0;

    std::cout << "Successful" << std::endl;

    delete alice;
    delete bob;

    uninit_rand_state();

    return 1;
}
