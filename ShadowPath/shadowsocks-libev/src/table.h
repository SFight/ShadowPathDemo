#ifndef PandaVPN_Table
#define PandaVPN_Table
#pragma once


static unsigned char encrypt_table[256];
static unsigned char decrypt_table[256];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundefined-inline"
inline void get_table(const unsigned char* key);
inline void table_encrypt(unsigned char *buf, size_t len);
inline void table_decrypt(unsigned char *buf, size_t len);
#pragma clang diagnostic pop

static unsigned int _i;
static unsigned long long _a;

#endif
