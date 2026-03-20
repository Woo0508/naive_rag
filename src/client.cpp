//
// Created by Antonia Januszewicz on 1/4/26.
//
#include "../include/client.h"

// 1. Take in Client query
Client::Client(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam,
        PrivateKey<DCRTPoly> skParam, size_t vectorParam, string query){
    cc = ccParam;
    pk = pkParam;
    sk = skParam;
    k = vectorParam;
    this->query = query;

}

// 2. Compute Client embedding
//convert string to ascii vector
vector<float_t> Client::embedQuery(std::string q) {
    
    vector<float_t> embedding;
    for (char c : q) 
    {
        embedding.push_back(static_cast<float_t>(c));
    }
    return embedding;
}

// 3. Send Client embedded query
//encrypt and send query
bool Client::sendClientEmbedding() {

    if (embeddedQuery.empty())
    {
        embedQuery(query);
    }
    
    int index = stoi(query);
    size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
    vector<double> oneHot(batchSize, 0.0);
    oneHot[index] = 1.0;
    Ciphertext<DCRTPoly> encryptedQuery = OpenFHEWrapper::encryptFromVector(cc, pk, oneHot);
    
    return true;

}

// 4. Receive query result
//get results back
vector<size_t> Client::receiveQueryResult() {
    // for testing returns empty
    return {};
}

// 5. Return final result
//convert vectros back to strings
vector<string> Client::decodeFinalResult() {

    vector<string> results;

    for (const auto& encryptedResult : encryptedResults) {

        vector<double> asciiValues = OpenFHEWrapper::decryptToVector(cc, sk, encryptedResult);
        string text;
        for (double val : asciiValues) 
        {
            if (abs(val) > 0.1) {
                char c = static_cast<char>(round(val));
                text += c;
            }
        }
        
        if (!text.empty()) {
            results.push_back(text);
        }

    }
    
    queryResult = results;
    return results;
}