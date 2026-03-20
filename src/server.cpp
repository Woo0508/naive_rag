//
// Created by Antonia Januszewicz on 1/4/26.
//
#include "../include/server.h"

// constructor
Server::Server(CryptoContext<DCRTPoly> ccParam, PublicKey<DCRTPoly> pkParam, size_t vectorParam){
    cc = ccParam;
    pk = pkParam;
    k = vectorParam;

}

// 2. Compute Similarity Scores
bool Server::computeSimilarity() {
    return false;
}

// 3. Compute Threshold
bool Server::computeThreshold() {
    return false;
}

// 4. Database Query
bool Server::databaseQuery() {
    
        if (databaseCipher.empty()) {
            cerr << "Error: database not loaded" << endl;
            return false;
        }
        
        queryResult.clear();
        
        size_t batchSize = cc->GetEncodingParams()->GetBatchSize();
        

        for (size_t i = 0; i < databaseCipher.size(); i++) {

            vector<Ciphertext<DCRTPoly>>& dbItem = databaseCipher[i];
            
            for (size_t bitIdx = 0; bitIdx < dbItem.size(); bitIdx++) {

                vector<double> maskVec(batchSize, 0.0);
                maskVec[i] = 1.0;
                Plaintext mask = cc->MakeCKKSPackedPlaintext(maskVec);
                
                Ciphertext<DCRTPoly> extractedSlot = cc->EvalMult(queryCipher, mask);
                cc->RelinearizeInPlace(extractedSlot);
                cc->RescaleInPlace(extractedSlot);
                Ciphertext<DCRTPoly> product = cc->EvalMult(extractedSlot, dbItem[bitIdx]);
                cc->RelinearizeInPlace(product);
                cc->RescaleInPlace(product);
                Ciphertext<DCRTPoly> summed = OpenFHEWrapper::sumAllSlots(cc, product);
                

                queryResult.push_back(summed);
            }
        }
        

}

// 5. Format and Return Query Result
bool Server::saveResult() {
    
    if (queryResult.empty()) {
        cerr << "Error: No results to save" << endl;
        return false;
    }
        
    cout << "Query result ready to send to client (" << queryResult.size() << " ciphertexts)" << endl;

    // just returns success without sending to client
    return true;
    
}



// takes binary vector
// converts to encrypted ciphertext
// stores in databaseCipher for databaseQuery to use
bool Server::loadAndEncryptBinaryDatabase(const vector<vector<int>>& binaryStrings) {

    databaseCipher.clear();

    for (const auto& binaryVec : binaryStrings) 
    {
        vector<Ciphertext<DCRTPoly>> encryptedBits;
        for (int bit : binaryVec) {

            vector<double> doubleVec(k, 0.0);
            doubleVec[0] = static_cast<double>(bit);
            Ciphertext<DCRTPoly> encrypted = OpenFHEWrapper::encryptFromVector(cc, pk, doubleVec);
            encryptedBits.push_back(encrypted);

        }

        databaseCipher.push_back(encryptedBits);
    }
}

//get queryResult
vector<Ciphertext<DCRTPoly>> Server::getQueryResult() {
    return queryResult;
}