# CKKS_dataset
Dataset and encryption
In this file, a function will generate a huge dataset of threat severity.
It uses batch encryption, with a batch size of 8192 elements per ciphertext. 
High-throughput encrypted analytics and calculates the mean and standard deviation.
It gives the results of time, execution speed and decrypted values

Execution commands:
g++ -std=c++17 -lcurl -I /usr/local/include/openfhe -L /usr/local/lib -lopenfhe-helib ckks_bgv_api_experiment.cpp -o he_experiment
./he_experiment

Update the path with your local path
