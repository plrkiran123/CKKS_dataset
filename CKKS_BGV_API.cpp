#include <iostream>
#include <vector>
#include <curl/curl.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

size_t WriteCallback(void *contents, size_t size, size_t nmemb, string *output) {
    size_t total_size = size * nmemb;
    output->append((char*)contents, total_size);
    return total_size;
}

vector<double> FetchThreatDataFromAPI(const string &url) {
    CURL *curl;
    CURLcode res;
    string response_data;
    vector<double> dataset;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            cerr << "Error fetching data from API: " << curl_easy_strerror(res) << endl;
            exit(1);
        }
    } else {
        cerr << "CURL initialization failed!" << endl;
        exit(1);
    }

    stringstream ss(response_data);
    string line, value;
    bool first_line = true;

    while (getline(ss, line)) {
        if (first_line) {  
            first_line = false;
            continue;
        }

        stringstream lineStream(line);
        getline(lineStream, value, ','); 
        getline(lineStream, value, ','); 

        dataset.push_back(stod(value));
    }

    return dataset;
}

// Benchmark function
void PrintExecutionTime(const string &operation, chrono::high_resolution_clock::time_point start, chrono::high_resolution_clock::time_point end) {
    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
    cout << operation << " Execution Time: " << duration << " ms" << endl;
}

// Function to choose encryption scheme based on dataset type
string SelectEncryptionScheme(bool isFloatingPoint) {
    return (isFloatingPoint) ? "CKKS" : "BGV";
}

int main() {
    string scheme_choice, api_url;
    int dataset_type, dataset_size, multiplicative_depth, batch_size, scaling_factor, lattice_size;

    // User selects dataset type
    cout << "Select Dataset Type: \n1. Floating-point Threat Scores \n2. Integer-based Threat Counts\n";
    cin >> dataset_type;

    // Automatically choose encryption scheme
    if (dataset_type == 1) {
        scheme_choice = "CKKS";
    } else if (dataset_type == 2) {
        scheme_choice = "BGV";
    } else {
        cout << "Invalid selection. Defaulting to CKKS." << endl;
        scheme_choice = "CKKS";
    }

    cout << "Selected Encryption Scheme: " << scheme_choice << endl;

    // API URL input
    cout << "Enter API URL for Threat Intelligence Data: ";
    cin >> api_url;

    // User input for parameters
    cout << "Enter dataset size (10000 - 10000000): ";
    cin >> dataset_size;

    cout << "Enter multiplicative depth (default: 6): ";
    cin >> multiplicative_depth;

    cout << "Enter batch size (default: 8192): ";
    cin >> batch_size;

    cout << "Enter scaling factor (default: 50 for CKKS, 65537 for BGV): ";
    cin >> scaling_factor;

    cout << "Choose Lattice Size (8192 / 16384 / 32768): ";
    cin >> lattice_size;

    // Fetch dataset from API
    cout << "Fetching data from API..." << endl;
    vector<double> threat_scores = FetchThreatDataFromAPI(api_url);
    if (threat_scores.size() < dataset_size) {
        dataset_size = threat_scores.size();
    }
    threat_scores.resize(dataset_size);

    // Initialize CryptoContext
    CryptoContext<DCRTPoly> cc;
    if (scheme_choice == "CKKS") {
        CCParams<CryptoContextCKKS> parameters;
        parameters.SetMultiplicativeDepth(multiplicative_depth);
        parameters.SetScalingModSize(scaling_factor);
        parameters.SetBatchSize(batch_size);
        parameters.SetRingDim(lattice_size);
        cc = GenCryptoContext(parameters);
    } else {
        CCParams<CryptoContextBGV> parameters;
        parameters.SetMultiplicativeDepth(multiplicative_depth);
        parameters.SetPlaintextModulus(scaling_factor);
        parameters.SetRingDim(lattice_size);
        cc = GenCryptoContext(parameters);
    }

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    // Generate keys
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalRotateKeyGen(keyPair.secretKey, {1, -1});

    // Encrypt threat data
    auto start_enc = chrono::high_resolution_clock::now();
    auto plaintext = cc->MakePackedPlaintext(threat_scores);
    auto ciphertext = cc->Encrypt(keyPair.publicKey, plaintext);
    auto end_enc = chrono::high_resolution_clock::now();
    PrintExecutionTime("Encryption", start_enc, end_enc);

    // Perform Homomorphic Computation
    auto start_comp = chrono::high_resolution_clock::now();
    auto sum_cipher = ciphertext;
    for (size_t i = 1; i < dataset_size; i++) {
        auto rotated_cipher = cc->EvalRotate(ciphertext, i);
        sum_cipher = cc->EvalAdd(sum_cipher, rotated_cipher);
    }
    auto divisor = cc->MakePackedPlaintext({(double)dataset_size});
    auto mean_cipher = cc->EvalMult(sum_cipher, divisor);
    auto end_comp = chrono::high_resolution_clock::now();
    PrintExecutionTime("Homomorphic Computation", start_comp, end_comp);

    // Decrypt Results
    auto start_dec = chrono::high_resolution_clock::now();
    Plaintext mean_decrypted;
    cc->Decrypt(keyPair.secretKey, mean_cipher, &mean_decrypted);
    auto end_dec = chrono::high_resolution_clock::now();
    PrintExecutionTime("Decryption", start_dec, end_dec);

    cout << "Decrypted Mean Threat Score: " << mean_decrypted << endl;

    return 0;
}
