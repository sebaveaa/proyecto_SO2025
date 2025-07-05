#ifndef SHA256_H
#define SHA256_H

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>

class SHA256 {
private:
    static const uint32_t k[];
    static const uint32_t sha256_h[];
    
    uint32_t rotr(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }
    
    uint32_t choose(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    
    uint32_t majority(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    uint32_t sig0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    
    uint32_t sig1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }
    
    void transform(const uint8_t* data, uint32_t h[8]);
    
public:
    std::string operator()(const std::string& input);
};

// Constantes SHA-256
const uint32_t SHA256::k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const uint32_t SHA256::sha256_h[] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

void SHA256::transform(const uint8_t* data, uint32_t h[8]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h_local;
    
    // Preparar el mensaje
    for (int i = 0; i < 16; i++) {
        w[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) |
               (data[i * 4 + 2] << 8) | data[i * 4 + 3];
    }
    
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    
    // Inicializar variables
    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; h_local = h[7];
    
    // Bucle principal
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = sig1(e);
        uint32_t ch = choose(e, f, g);
        uint32_t temp1 = h_local + S1 + ch + k[i] + w[i];
        uint32_t S0 = sig0(a);
        uint32_t maj = majority(a, b, c);
        uint32_t temp2 = S0 + maj;
        
        h_local = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    
    // Sumar al hash
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_local;
}

std::string SHA256::operator()(const std::string& input) {
    std::vector<uint8_t> data(input.begin(), input.end());
    uint64_t bit_len = data.size() * 8;
    
    // Padding
    data.push_back(0x80);
    while (data.size() % 64 != 56) {
        data.push_back(0x00);
    }
    
    // Añadir longitud
    for (int i = 7; i >= 0; i--) {
        data.push_back((bit_len >> (i * 8)) & 0xff);
    }
    
    // Inicializar hash
    uint32_t h[8];
    for (int i = 0; i < 8; i++) {
        h[i] = sha256_h[i];
    }
    
    // Procesar en bloques de 512 bits
    for (size_t i = 0; i < data.size(); i += 64) {
        transform(&data[i], h);
    }
    
    // Convertir a string hexadecimal
    std::stringstream ss;
    for (int i = 0; i < 8; i++) {
        ss << std::hex << std::setw(8) << std::setfill('0') << h[i];
    }
    
    return ss.str();
}

#endif // SHA256_H 