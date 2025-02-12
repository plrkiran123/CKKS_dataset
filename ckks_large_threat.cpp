#include <iostream>
#include <vector>
#include <chrono>
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

vector<double> GenerateLargeThreatDataset(size_t data_size) {
    vector<double> dataset;
    dataset.reserve(data_size);
    srand(time(nullptr)); 
    for (size_t i = 0; i < data_size; i++) {
        dataset.push_back((rand() % 1000) / 1000.0); 
    }
    return dataset;
}

void PrintExecutionTime(const string& operation, chrono::high_resolution_clock::time_point start, chrono::high_resolution_clock::time_point end) {
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    cout << operation << " Execution Time: " << duration << " ms" << endl;
}

int main() {
    CCParams<CryptoContextCKKS> parameters;
    parameters.SetMultiplicativeDepth(6); 
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(8192); 

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalRotateKeyGen(keyPair.secretKey, {1, -1});

    size_t dataset_size = 1'000'000; // 1 million records
    cout << "Generating Large Threat Dataset: " << dataset_size << " records..." << endl;
    vector<double> threat_scores = GenerateLargeThreatDataset(dataset_size);

    auto start_enc = chrono::high_resolution_clock::now();
    auto plaintext = cc->MakeCKKSPackedPlaintext(threat_scores);
    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    auto end_enc = chrono::high_resolution_clock::now();
    PrintExecutionTime("Encryption", start_enc, end_enc);

    auto start_comp = chrono::high_resolution_clock::now();
    
    auto sum_cipher = ciphertext;
    for (size_t i = 1; i < dataset_size; i++) {
        auto rotated_cipher = cc->EvalRotate(ciphertext, i);
        sum_cipher = cc->EvalAdd(sum_cipher, rotated_cipher);
    }

    auto divisor = cc->MakeCKKSPackedPlaintext({(double)dataset_size});
    auto mean_cipher = cc->EvalMult(sum_cipher, divisor);
    
    auto squared_scores = cc->EvalMult(ciphertext, ciphertext);
    auto squared_sum = squared_scores;
    for (size_t i = 1; i < dataset_size; i++) {
        auto rotated_cipher = cc->EvalRotate(squared_scores, i);
        squared_sum = cc->EvalAdd(squared_sum, rotated_cipher);
    }
    
    auto mean_squared = cc->EvalMult(mean_cipher, mean_cipher);
    auto variance_cipher = cc->EvalSub(squared_sum, mean_squared);
    auto stddev_cipher = cc->EvalMult(variance_cipher, cc->MakeCKKSPackedPlaintext({0.5}));

    auto end_comp = chrono::high_resolution_clock::now();
    PrintExecutionTime("Homomorphic Computation", start_comp, end_comp);

    auto start_dec = chrono::high_resolution_clock::now();
    Plaintext mean_decrypted, stddev_decrypted;
    cc->Decrypt(keyPair.secretKey, mean_cipher, &mean_decrypted);
    cc->Decrypt(keyPair.secretKey, stddev_cipher, &stddev_decrypted);
    auto end_dec = chrono::high_resolution_clock::now();
    PrintExecutionTime("Decryption", start_dec, end_dec);

    mean_decrypted->SetLength(1);
    stddev_decrypted->SetLength(1);

    cout << "Decrypted Mean Threat Score: " << mean_decrypted << endl;
    cout << "Decrypted Standard Deviation: " << stddev_decrypted << endl;

    return 0;
}
