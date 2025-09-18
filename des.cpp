#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>

using namespace std;

// DES tables (standard)
static const int IP[64] = {
  58,50,42,34,26,18,10,2,
  60,52,44,36,28,20,12,4,
  62,54,46,38,30,22,14,6,
  64,56,48,40,32,24,16,8,
  57,49,41,33,25,17,9,1,
  59,51,43,35,27,19,11,3,
  61,53,45,37,29,21,13,5,
  63,55,47,39,31,23,15,7
};

static const int IP_INV[64] = {
  40,8,48,16,56,24,64,32,
  39,7,47,15,55,23,63,31,
  38,6,46,14,54,22,62,30,
  37,5,45,13,53,21,61,29,
  36,4,44,12,52,20,60,28,
  35,3,43,11,51,19,59,27,
  34,2,42,10,50,18,58,26,
  33,1,41,9,49,17,57,25
};

static const int E[48] = {
  32,1,2,3,4,5,
  4,5,6,7,8,9,
  8,9,10,11,12,13,
  12,13,14,15,16,17,
  16,17,18,19,20,21,
  20,21,22,23,24,25,
  24,25,26,27,28,29,
  28,29,30,31,32,1
};

static const int P[32] = {
  16,7,20,21,29,12,28,17,
  1,15,23,26,5,18,31,10,
  2,8,24,14,32,27,3,9,
  19,13,30,6,22,11,4,25
};

static const int PC1[56] = {
  57,49,41,33,25,17,9,
  1,58,50,42,34,26,18,
  10,2,59,51,43,35,27,
  19,11,3,60,52,44,36,
  63,55,47,39,31,23,15,
  7,62,54,46,38,30,22,
  14,6,61,53,45,37,29,
  21,13,5,28,20,12,4
};

static const int PC2[48] = {
  14,17,11,24,1,5,
  3,28,15,6,21,10,
  23,19,12,4,26,8,
  16,7,27,20,13,2,
  41,52,31,37,47,55,
  30,40,51,45,33,48,
  44,49,39,56,34,53,
  46,42,50,36,29,32
};

static const int SHIFTS[16] = {
  1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};

// S-boxes: S[box][row][col]
static const int S[8][4][16] = {
  { // S1
    {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
    {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
  },
  { // S2
    {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
    {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
    {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
    {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
  },
  { // S3
    {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
    {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
    {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
    {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
  },
  { // S4
    {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
    {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
  },
  { // S5
    {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
    {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
    {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
  },
  { // S6
    {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
    {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
    {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
  },
  { // S7
    {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
  },
  { // S8
    {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
  }
};

int hexCharToInt(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return 0;
}

vector<int> hexToBits64(const string& hex) {
    vector<int> bits;
    bits.reserve(64);
    for (char c : hex) {
        int v = hexCharToInt(c);
        for (int b = 3; b >= 0; --b) {
            bits.push_back((v >> b) & 1);
        }
    }
    return bits; // size should be 4 * hex.length()
}

string bits64ToHex(const vector<int>& bits) {
    const char* hexmap = "0123456789ABCDEF";
    string out;
    out.reserve(bits.size() / 4);
    for (size_t i = 0; i < bits.size(); i += 4) {
        int val = (bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | (bits[i + 3]);
        out.push_back(hexmap[val & 0xF]);
    }
    return out;
}

vector<int> permute(const vector<int>& in, const int table[], int tableSize) {
    vector<int> out(tableSize);
    for (int i = 0; i < tableSize; ++i) {
        out[i] = in[table[i] - 1];
    }
    return out;
}

vector<int> leftShift28(const vector<int>& in, int shifts) {
    vector<int> out(28);
    for (int i = 0; i < 28; ++i) out[i] = in[(i + shifts) % 28];
    return out;
}

vector<vector<int>> generateRoundKeys(const string& keyHex) {
    vector<int> keyBits = hexToBits64(keyHex); // 64 bits
    vector<int> perm56 = permute(keyBits, PC1, 56); // 56 bits
    vector<int> c(28), d(28);
    for (int i = 0; i < 28; ++i) c[i] = perm56[i];
    for (int i = 0; i < 28; ++i) d[i] = perm56[i + 28];

    vector<vector<int>> roundKeys; roundKeys.reserve(16);
    for (int round = 0; round < 16; ++round) {
        c = leftShift28(c, SHIFTS[round]);
        d = leftShift28(d, SHIFTS[round]);
        vector<int> cd(56);
        for (int i = 0; i < 28; ++i) cd[i] = c[i];
        for (int i = 0; i < 28; ++i) cd[28 + i] = d[i];
        vector<int> subKey = permute(cd, PC2, 48);
        roundKeys.push_back(subKey);
    }
    return roundKeys;
}

vector<int> xorVectors(const vector<int>& a, const vector<int>& b) {
    vector<int> out(a.size());
    for (size_t i = 0; i < a.size(); ++i) out[i] = a[i] ^ b[i];
    return out;
}

vector<int> sboxTransform(const vector<int>& sixBits, int box) {
    // sixBits: size 6, box in 0..7
    int row = (sixBits[0] << 1) | sixBits[5];
    int col = (sixBits[1] << 3) | (sixBits[2] << 2) | (sixBits[3] << 1) | sixBits[4];
    int val = S[box][row][col];
    vector<int> out(4);
    for (int i = 3; i >= 0; --i) {
        out[3 - i] = ((val >> i) & 1);
    }
    return out;
}

vector<int> fFunction(const vector<int>& r32, const vector<int>& subKey48) {
    // Expand
    vector<int> expanded = permute(r32, E, 48); // size 48
    // XOR with subkey
    vector<int> x = xorVectors(expanded, subKey48);
    // S-boxes
    vector<int> sOut; sOut.reserve(32);
    for (int i = 0; i < 8; ++i) {
        vector<int> six(6);
        for (int j = 0; j < 6; ++j) six[j] = x[i * 6 + j];
        vector<int> four = sboxTransform(six, i);
        // four contains 4 bits in order msb->lsb in four[0..3] as we set
        for (int k = 0; k < 4; ++k) sOut.push_back(four[k]);
    }
    // P permutation
    vector<int> pOut = permute(sOut, P, 32);
    return pOut;
}

vector<int> desEncryptBlockBits(const vector<int>& plaintextBits64, const vector<vector<int>>& roundKeys) {
    // Initial permutation
    vector<int> ip = permute(plaintextBits64, IP, 64);
    vector<int> L(32), R(32);
    for (int i = 0; i < 32; ++i) { L[i] = ip[i]; R[i] = ip[i + 32]; }

    // 16 rounds
    for (int i = 0; i < 16; ++i) {
        vector<int> prevL = L;
        vector<int> prevR = R;
        vector<int> f = fFunction(prevR, roundKeys[i]);
        vector<int> newR = xorVectors(prevL, f);
        L = prevR;
        R = newR;
    }

    // Preoutput: R || L (notice final swap)
    vector<int> preout(64);
    for (int i = 0; i < 32; ++i) preout[i] = R[i];
    for (int i = 0; i < 32; ++i) preout[32 + i] = L[i];

    // Apply final permutation (IP inverse)
    vector<int> cipherBits = permute(preout, IP_INV, 64);
    return cipherBits;
}

string desEncryptHex(const string& plainHex, const string& keyHex) {
    if (plainHex.size() != 16 || keyHex.size() != 16) {
        throw runtime_error("Plaintext and key must each be 16 hex characters (64 bits).");
    }
    vector<int> plainBits = hexToBits64(plainHex);
    vector<vector<int>> keys = generateRoundKeys(keyHex);
    vector<int> cipherBits = desEncryptBlockBits(plainBits, keys);
    return bits64ToHex(cipherBits);
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    // Classic test vector
    string M = "0123456789ABCDEF";
    string K = "133457799BBCDFF1";

    cout << "DES encryption demo (single-block, 64-bit hex strings)\n";
    cout << "Plaintext M = " << M << "\n";
    cout << "Key       K = " << K << "\n";

    string ciphertext;
    try {
        ciphertext = desEncryptHex(M, K);
        cout << "Ciphertext C = " << ciphertext << "\n";
        cout << "(expected: 85E813540F0AB405)\n";
    }
    catch (exception& e) {
        cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    // Allow custom input
    cout << "\nEnter custom plaintext (16 hex chars) or blank to skip: ";
    string customP;
    if (getline(cin, customP)) {
        if (!customP.empty()) {
            cout << "Enter custom key (16 hex chars): ";
            string customK;
            getline(cin, customK);
            try {
                string c2 = desEncryptHex(customP, customK);
                cout << "Ciphertext = " << c2 << "\n";
            }
            catch (exception& e) {
                cout << "Error: " << e.what() << "\n";
            }
        }
        else {
            cout << "No custom input. Exiting.\n";
        }
    }

    return 0;
}
