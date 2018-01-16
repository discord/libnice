#include <assert.h>

#include <openssl/md5.h>
#include <openssl/hmac.h>

#include "rand.h"
#include "stunhmac.h"

void stun_sha1 (const uint8_t *msg, size_t len, size_t msg_len,
    uint8_t *sha, const void *key, size_t keylen, int padding) {
  uint16_t fakelen = htons(msg_len);
  uint8_t pad_char[64] = {0};
  HMAC_CTX handle;

#ifdef NDEBUG
#define TRY(x) x;
#else
  int ret;
#define TRY(x)                                  \
  ret = x;                                      \
  assert (ret >= 0);
#endif

  assert (len >= 44u);

  HMAC_CTX_init(&handle);
  TRY(HMAC_Init(&handle, key, keylen, EVP_sha1()));

  TRY(HMAC_Update(&handle, msg, 2));
  TRY(HMAC_Update(&handle, (unsigned char*)&fakelen, 2));
  TRY(HMAC_Update(&handle, msg + 4, len - 28));

  /* RFC 3489 specifies that the message's size should be 64 bytes,
     and \x00 padding should be done */
  if (padding && ((len - 24) % 64) > 0) {
    uint16_t pad_size = 64 - ((len - 24) % 64);

    TRY(HMAC_Update(&handle, pad_char, pad_size));
  }

  unsigned int shalen;
  HMAC_Final(&handle, sha, &shalen);
  assert(shalen == 20);

  HMAC_CTX_cleanup(&handle);
  HMAC_cleanup(&handle);
}

static const uint8_t *priv_trim_var(const uint8_t *var, size_t *var_len)
{
  const uint8_t *ptr = var;

  while (*ptr == '"') {
    ptr++;
    (*var_len)--;
  }
  while(ptr[*var_len-1] == '"' ||
      ptr[*var_len-1] == 0) {
    (*var_len)--;
  }

  return ptr;
}

void stun_hash_creds(const uint8_t *realm, size_t realm_len,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    unsigned char md5[16]) {

  const uint8_t *username_trimmed = priv_trim_var (username, &username_len);
  const uint8_t *password_trimmed = priv_trim_var (password, &password_len);
  const uint8_t *realm_trimmed = priv_trim_var (realm, &realm_len);
  const uint8_t *colon = (uint8_t *)":";
  MD5_CTX handle;

  MD5_Init(&handle);
  MD5_Update(&handle, username_trimmed, username_len);
  MD5_Update(&handle, colon, 1);
  MD5_Update(&handle, realm_trimmed, realm_len);
  MD5_Update(&handle, colon, 1);
  MD5_Update(&handle, password_trimmed, password_len);

  MD5_Final(md5, &handle);
}

void stun_make_transid(StunTransactionId id) {
  nice_RAND_nonce (id, 16);
}
