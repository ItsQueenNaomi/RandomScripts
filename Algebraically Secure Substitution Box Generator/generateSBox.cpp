/*
  AAlgebraically Secure (Key-Dependent) Substitution Box Generator
  Copyright (C) 2024  Aristotle Daskaleas

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.

  Compile with 'DEBUG' flag to enable security evaluation for each generated SBox.
  
  The security evaluations might not be the best, please feel free to submit a pull request
  (or just change it on your local copy) if you believe you can tune them better.

  Requires OpenSSL >=3.0
*/

#include <iostream>
#include <iomanip>
#include <vector>
#include <openssl/sha.h>

#ifdef DEBUG
#include <numeric>
#include <set>
#include <map>
#include <string>
#include <cstring>
#include <cstdint>

// ----- Extended Differential Uniformity Analysis -----

struct DifferentialStats {
    int maxCount;
    double average;
    double stdDeviation;
    std::vector<int> histogram; // histogram: index = differential count, value = frequency
};

DifferentialStats calculateExtendedDifferentialStats(const uint8_t sbox[256]) {
    int totalEntries = 255 * 256; // excluding a = 0
    std::vector<int> counts;
    counts.reserve(totalEntries);
    int maxCount = 0;
    
    for (int a = 1; a < 256; a++) {
        int diffCounts[256] = {0};
        for (int x = 0; x < 256; x++) {
            int y = sbox[x] ^ sbox[x ^ a];
            diffCounts[y]++;
        }
        for (int y = 0; y < 256; y++) {
            counts.push_back(diffCounts[y]);
            if (diffCounts[y] > maxCount)
                maxCount = diffCounts[y];
        }
    }
    
    double sum = std::accumulate(counts.begin(), counts.end(), 0.0);
    double avg = sum / counts.size();
    double variance = 0.0;
    for (int v : counts) {
        variance += (v - avg) * (v - avg);
    }
    variance /= counts.size();
    double stdDev = std::sqrt(variance);
    
    // Build histogram for counts from 0 to maxCount.
    std::vector<int> histogram(maxCount + 1, 0);
    for (int v : counts) {
        histogram[v]++;
    }
    
    DifferentialStats stats { maxCount, avg, stdDev, histogram };
    return stats;
}

// ----- Extended Walsh Analysis for a Boolean Function -----
// Compute the full Walsh coefficients for a Boolean function f: {0,1}^8 -> {0,1}
std::vector<int> computeFullWalshCoefficients(const int f[256]) {
    std::vector<int> walshCoeffs;
    walshCoeffs.reserve(255);
    for (int a = 1; a < 256; a++) {
        int sum = 0;
        for (int x = 0; x < 256; x++) {
            int dot = 0;
            int temp = a & x;
            while (temp) {
                dot ^= (temp & 1);
                temp >>= 1;
            }
            int sign = ((f[x] ^ dot) == 0) ? 1 : -1;
            sum += sign;
        }
        walshCoeffs.push_back(sum);
    }
    return walshCoeffs;
}

struct WalshStats {
    int maxAbs;
    double averageAbs;
    double stdDeviationAbs;
};

WalshStats calculateWalshStats(const int f[256]) {
    std::vector<int> walshCoeffs = computeFullWalshCoefficients(f);
    std::vector<int> absCoeffs;
    absCoeffs.reserve(walshCoeffs.size());
    for (int val : walshCoeffs) {
        absCoeffs.push_back(std::abs(val));
    }
    int maxAbs = *std::max_element(absCoeffs.begin(), absCoeffs.end());
    double sumAbs = std::accumulate(absCoeffs.begin(), absCoeffs.end(), 0.0);
    double avgAbs = sumAbs / absCoeffs.size();
    double variance = 0.0;
    for (int v : absCoeffs) {
        variance += (v - avgAbs) * (v - avgAbs);
    }
    variance /= absCoeffs.size();
    double stdDevAbs = std::sqrt(variance);
    
    return { maxAbs, avgAbs, stdDevAbs };
}

// ----- Algebraic Degree Analysis -----
// Compute the algebraic degree of a Boolean function f given its truth table (256 values).
// We use a Möbius transform to compute the Algebraic Normal Form (ANF) coefficients.
int computeAlgebraicDegree(const int f[256]) {
    int coeff[256];
    for (int i = 0; i < 256; i++) {
        coeff[i] = f[i];
    }
    // Möbius transform (in-place)
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 256; j++) {
            if (j & (1 << i)) {
                coeff[j] ^= coeff[j ^ (1 << i)];
            }
        }
    }
    int maxDegree = 0;
    for (int j = 0; j < 256; j++) {
        if (coeff[j] != 0) {
            int degree = 0;
            int temp = j;
            while (temp) {
                degree += (temp & 1);
                temp >>= 1;
            }
            if (degree > maxDegree)
                maxDegree = degree;
        }
    }
    return maxDegree;
}

// ----- Extended S-Box Analysis -----
// For each output bit of the S-box, compute nonlinearity, Walsh stats, and algebraic degree.
struct SBoxAnalysis {
    int minNonlinearity;
    int maxNonlinearity;
    double avgNonlinearity;
    int minAlgebraicDegree;
    int maxAlgebraicDegree;
	int differentialUniformity;
	double stdDevDifferentialDistribution;
};

int nonlinearity(const int sbox[256]) {
    int min_nonlinearity = 256; // start with a high number

    for (int affine = 0; affine < 256; affine++) {
        int distance = 0;
        for (int x = 0; x < 256; x++) {
            int y1 = sbox[x];
            int y2 = (x ^ affine); // affine approximation
            distance += (y1 != y2);
        }
        min_nonlinearity = std::min(min_nonlinearity, distance);
    }

    return min_nonlinearity;
}


int differential_uniformity(const int sbox[256]) {
    std::map<int, int> output_counts;
    int max_count = 0;

    for (int input_diff = 0; input_diff < 256; input_diff++) {
        for (int x = 0; x < 256; x++) {
            int y1 = sbox[x];
            int y2 = sbox[x ^ input_diff];
            int output_diff = y1 ^ y2;
            output_counts[output_diff]++;
        }
    }

    for (const auto& entry : output_counts) {
        max_count = std::max(max_count, entry.second);
    }

    return max_count; // Return the maximum count of differential output differences
}

double differential_distribution(const int sbox[256]) {
    std::vector<int> dist(256, 0); // to store counts for each output difference

    for (int input_diff = 0; input_diff < 256; input_diff++) {
        for (int x = 0; x < 256; x++) {
            int y1 = sbox[x];
            int y2 = sbox[x ^ input_diff];
            int output_diff = y1 ^ y2;
            dist[output_diff]++;
        }
    }

    double sum = 0.0;
    for (int count : dist) {
        sum += count;
    }
    double average = sum / dist.size();

    double variance = 0.0;
    for (int count : dist) {
        variance += (count - average) * (count - average);
    }
    double stddev = std::sqrt(variance / dist.size());

    std::cout << "Differential Distribution: Average = " << average << ", Std Dev = " << stddev << std::endl;
    return stddev;
}


SBoxAnalysis analyzeSBox(const uint8_t sbox[256]) {
    int totalNL = 0;
    int minNL = 256, maxNL = 0;
    int totalDegree = 0;
    int minDegree = 8, maxDegree = 0;

	// Compute nonlinearity and algebraic degree (per output bit)
    for (int bit = 0; bit < 8; bit++) {
        int f[256];
        for (int x = 0; x < 256; x++) {
            f[x] = (sbox[x] >> bit) & 1;
        }
        int nl = nonlinearity(f);
        totalNL += nl;
        minNL = std::min(minNL, nl);
        maxNL = std::max(maxNL, nl);
        
        int degree = computeAlgebraicDegree(f);
        totalDegree += degree;
        minDegree = std::min(minDegree, degree);
        maxDegree = std::max(maxDegree, degree);
    }

	// Compute Differential Distribution Table (DDT)
	int diffCounts[256] = {0};
	int totalDiffValues = 0;
	double sumDiff = 0.0, sumDiffSquared = 0.0;
	int maxDiffCount = 0;

    // Track unique differential outputs
    std::set<int> uniqueDiffs; 

    for (int a = 1; a < 256; a++) { // Nonzero input difference
        int localDiffCounts[256] = {0};
        for (int x = 0; x < 256; x++) {
            int y = sbox[x] ^ sbox[x ^ a];
            localDiffCounts[y]++;
            uniqueDiffs.insert(y); // Store unique differentials
        }
        for (int y = 0; y < 256; y++) {
            diffCounts[y] += localDiffCounts[y];
            maxDiffCount = std::max(maxDiffCount, localDiffCounts[y]);
        }
    }

    // Print unique differential values count
    std::cout << "Unique Differential Outputs: " << uniqueDiffs.size() << std::endl;

	double meanDiff = (totalDiffValues > 0) ? (sumDiff / totalDiffValues) : 0.0;
	double varianceDiff = (totalDiffValues > 0) ? ((sumDiffSquared / totalDiffValues) - (meanDiff * meanDiff)) : 0.0;
	double stdDevDiff = (varianceDiff >= 0) ? std::sqrt(varianceDiff) : 0.0;

    std::cout << "Differential Distribution Counts: ";
    for (int i = 0; i < 16; i++) {
        std::cout << diffCounts[i] << " ";
    }
    std::cout << std::endl;

    int SBOX[256];
    for (size_t i = 0; i < 256; ++i) {
        SBOX[i] = static_cast<int>(sbox[i]);
    }

	// Populate the structure
    SBoxAnalysis analysis;
    analysis.minNonlinearity = minNL;
    analysis.maxNonlinearity = maxNL;
    analysis.avgNonlinearity = totalNL / 8.0;
    analysis.minAlgebraicDegree = minDegree;
    analysis.maxAlgebraicDegree = maxDegree;
	analysis.differentialUniformity = differential_uniformity(SBOX);
	analysis.stdDevDifferentialDistribution = differential_distribution(SBOX);
    
	return analysis;
}

// ----- Comprehensive S-box Security Report -----
void printSBoxSecurityReport(const uint8_t sbox[256]) {
    // Basic metrics
    int diffUniformity = calculateExtendedDifferentialStats(sbox).maxCount;
    
    DifferentialStats dStats = calculateExtendedDifferentialStats(sbox);
    std::cout << "Differential Uniformity (max count): " << dStats.maxCount << std::endl;
    std::cout << "Differential Distribution: Average = " << dStats.average
              << ", Std Dev = " << dStats.stdDeviation << std::endl;
    
    // S-box Boolean function analysis
    SBoxAnalysis analysis = analyzeSBox(sbox);
    std::cout << "Min Nonlinearity: " << analysis.minNonlinearity << std::endl;
    std::cout << "Max Nonlinearity: " << analysis.maxNonlinearity << std::endl;
    std::cout << "Avg Nonlinearity: " << analysis.avgNonlinearity << std::endl;

    std::cout << "Differential Uniformity: " << analysis.differentialUniformity << std::endl;
    //std::cout << "Std Dev Differential Distribution: " << analysis.stdDevDifferentialDistribution << std::endl;

    std::cout << "Algebraic Degree: Min = " << analysis.minAlgebraicDegree
            << ", Max = " << analysis.maxAlgebraicDegree << std::endl;

    
    // Composite security score (ideal: DU=4, NL=112)
    double scoreNL = static_cast<double>(analysis.minNonlinearity) / 112.0;
    double scoreDU = 4.0 / static_cast<double>(diffUniformity);
	double scoreAD = static_cast<double>(analysis.minAlgebraicDegree) / 7.0;

	// Additional precision factors
    double scoreDDD = 1.0 / (1.0 + analysis.stdDevDifferentialDistribution);
    double scoreNLS = 1.0 / (1.0 + (analysis.maxNonlinearity - analysis.minNonlinearity));

    std::cout << "ScoreNL: " << scoreNL << ", ScoreDU: " << scoreDU
          << ", ScoreAD: " << scoreAD << ", ScoreDDD: " << scoreDDD
          << ", ScoreNLS: " << scoreNLS << std::endl;

	// Composite weighted score
	double compositeScore = (0.4 * scoreNL) + (0.3 * scoreDU) + (0.2 * scoreAD) +
	(0.05 * scoreDDD) + (0.05 * scoreNLS);

    std::cout << "Composite S-box Security Score: " << compositeScore << std::endl;
}
#endif

// ------------------- GF(2^8) Arithmetic -------------------

// Multiply two numbers in GF(2^8) using the irreducible polynomial 0x11B.
uint8_t gfMultiply(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1)
            p ^= a;
        bool hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set)
            a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

// Compute the multiplicative inverse in GF(2^8); define inverse(0)=0.
uint8_t multiplicativeInverse(uint8_t x) {
    if (x == 0)
        return 0;
    for (int i = 1; i < 256; i++) {
        if (gfMultiply(x, static_cast<uint8_t>(i)) == 1)
            return static_cast<uint8_t>(i);
    }
    return 0; // Should not reach here.
}

// ------------------- Key-Dependent Affine Transformation -------------------

// Compute the affine transform on an 8-bit value using a key-dependent 8x8 matrix A and vector b.
// The matrix A is provided as an array of 8 uint8_t values (each representing a row).
uint8_t affineTransform(uint8_t y, const uint8_t A[8], uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        // Compute the dot product (mod 2) of the i-th row of A and y.
        uint8_t row = A[i];
        uint8_t dot = 0;
        uint8_t temp = row & y;
        while (temp) {
            dot ^= (temp & 1);
            temp >>= 1;
        }
        // Set bit i to (dot XOR the i-th bit of b)
        result |= ((dot ^ ((b >> i) & 1)) << i);
    }
    return result;
}

// ------------------- Key Material to Matrix and Vector -------------------

// Check if an 8x8 binary matrix (represented as 8 bytes, one row each) is invertible over GF(2).
bool isInvertible(uint8_t A[8]) {
    // Make a copy for Gaussian elimination.
    uint8_t M[8];
    memcpy(M, A, 8);
    // Perform Gaussian elimination mod 2.
    for (int i = 0; i < 8; i++) {
        // Find pivot: bit i in row >= i should be 1.
        bool pivotFound = false;
        for (int j = i; j < 8; j++) {
            if ( (M[j] >> i) & 1 ) {
                // Swap rows i and j if needed.
                if(j != i) {
                    uint8_t temp = M[i];
                    M[i] = M[j];
                    M[j] = temp;
                }
                pivotFound = true;
                break;
            }
        }
        if (!pivotFound)
            return false;
        // Eliminate the pivot bit from all other rows.
        for (int j = 0; j < 8; j++) {
            if (j != i && ((M[j] >> i) & 1)) {
                M[j] ^= M[i];
            }
        }
    }
    return true;
}

// Generate an invertible 8x8 matrix (A) and an 8-bit vector (b) from a given key.
// This function uses SHA-256 to produce candidate bytes. If the candidate matrix is not invertible,
// we tweak one row.
void generateKeyDependentAffineParameters(const std::vector<uint8_t>& key, uint8_t A[8], uint8_t &b) {
    // Compute SHA-256 digest of the key.
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(key.data(), key.size(), hash);
    
    // Use first 8 bytes as candidate rows for A.
    for (int i = 0; i < 8; i++) {
        A[i] = hash[i];
        if (A[i] == 0) A[i] = 1;  // Avoid zero row.
    }
    
    // If the matrix is not invertible, tweak rows until it is.
    int attempt = 0;
    while (!isInvertible(A) && attempt < 256) {
        // Simple tweak: XOR one row with a constant.
        A[attempt % 8] ^= 0xFF;
        attempt++;
    }
    if (!isInvertible(A)) {
        std::cerr << "Failed to generate an invertible matrix from key." << std::endl;
        exit(1);
    }
    
    // Use the 9th byte of the hash as b (if zero, set to a nonzero value).
    b = hash[8];
    if (b == 0)
        b = 0x63; // Fall back to AES constant.
}

// ------------------- Key-Dependent S-box Generation -------------------

// Generate the keyed S-box. For each input x (0..255):
// If x is 0, define Inv(x)=0; otherwise, compute the multiplicative inverse in GF(2^8).
// Then apply the key-dependent affine transformation.
void generateKeyedSBox(const std::vector<uint8_t>& key, uint8_t sbox[256]) {
    uint8_t A[8];
    uint8_t b;
    generateKeyDependentAffineParameters(key, A, b);
    
    for (int x = 0; x < 256; x++) {
        uint8_t inv = (x == 0) ? 0 : multiplicativeInverse(static_cast<uint8_t>(x));
        sbox[x] = affineTransform(inv, A, b);
    }
}

// ------------------- Main Function -------------------

int main(int argc, char* argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "-h") == 0 || strncmp(argv[1], "-help", 5) == 0 || strncmp(argv[1], "--help", 6) == 0) {
            std::cerr << "Usage: " << argv[0] << " [\"Key\"]" << std::endl;
            std::cerr << "If \"Key\" is not specified, the default one will be used." << std::endl << std::endl;
            std::cerr << "Algebraically Secure (Key-Dependent) Substitution Box Generator" << std::endl;
            std::cerr << "Copyright (C) 2025 Aristotle Daskaleas" << std::endl;
            return 1;
        }
    }
    // Get key from command line argument or use a default.
    std::string keyStr = (argc > 1) ? argv[1] : "f3747742fb15d353162ebed3ba8d40943b8c222312889630c27261420094f3598c5e77cd9e189cbf66d36b64c847a4555ce16ee9bd650e393e56423f33c49139f5f40a6b3804c49fc9c17dc5cc66be9e3bafdce614072b463a23ec6b0f1654fa35397620865254715b9752514451d06207d523dcb282ef80133192ba491210a9";
    std::vector<uint8_t> key(keyStr.begin(), keyStr.end());
    
    uint8_t sbox[256];
    generateKeyedSBox(key, sbox);

    // Reached if key was able to generate an inversible S-BOX

#ifdef DEBUG
    std::cout << "S-box security report:" << std::endl;
    printSBoxSecurityReport(sbox); // SECURITY REPORT
    std::cout << std::endl;
#endif    

    // Print the generated keyed S-box.
    std::cout << "Key-dependent S-box:" << std::endl;
    for (int i = 0; i < 256; i++) {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(sbox[i]) << ", ";
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
    
    return 0;
}
