// General functionality header files
#include "include/config.h"
#include "include/vector_utils.h"
#include "include/openFHE_wrapper.h"
#include "openfhe.h"
#include <iostream>
#include <ctime>
#include <numeric>

#include "utils.cpp"
#include "include/client.h"
#include "include/server.h"

using namespace lbcrypto;
using namespace std;
using namespace VectorUtils;

//Helper to convert string to binary vector (ASCII)
vector<int> stringToBinaryVector(const string& text) {
    vector<int> bits;
    for (char c : text) 
    {
        for (int i = 7; i >= 0; i--) {
            bits.push_back((c >> i) & 1);
        }
    }
    return bits;
}

//Helper to convert binary vector to string
string binaryVectorToString(const vector<int>& bits) {
    string result;
    for (size_t i = 0; i + 7 < bits.size(); i += 8) {
        char c = 0;
        for (int j = 0; j < 8; j++) {
            c = (c << 1) | bits[i + j];
        }
        result += c;
    }
    return result;
}

int main(int argc, char *argv[]) {

    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <embedding_file> <faiss_file> <db_file>" << std::endl;
        return 1;
    }

    std::string embedding_file = argv[1];
    std::string faiss_file = argv[2];
    std::string database_file = argv[3];

    std::cout << "Embedding file: " << embedding_file << std::endl;
    std::cout << "Faiss file: " << faiss_file << std::endl;
    std::cout << "Database file: " << database_file << std::endl;

    // ===== CKKS SETUP =====
    size_t multDepth = OpenFHEWrapper::computeRequiredDepth(5);

    CryptoContext<DCRTPoly> cc;
    cc->ClearEvalMultKeys();
    cc->ClearEvalAutomorphismKeys();
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    PublicKey<DCRTPoly> pk;
    PrivateKey<DCRTPoly> sk;
    size_t batchSize;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(45);
    parameters.SetScalingTechnique(FIXEDMANUAL);

    cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    batchSize = cc->GetEncodingParams()->GetBatchSize();

    cout << "Generating key pair... " << endl;
    auto keyPair = cc->KeyGen();
    pk = keyPair.publicKey;
    sk = keyPair.secretKey;

    cout << "Generating mult keys... " << endl;
    cc->EvalMultKeyGen(sk);

    cout << "Generating sum keys... " << endl;
    cc->EvalSumKeyGen(sk);

    cout << "Generating rotation keys... " << endl;
    vector<int> rotationFactors(VECTOR_DIM-1);
    iota(rotationFactors.begin(), rotationFactors.end(), 1);
    for(int i = VECTOR_DIM; i < int(batchSize); i *= 2) {
        rotationFactors.push_back(i);
    }
    for(int i = 1; i < int(batchSize); i *= 2) {
        rotationFactors.push_back(-i);
    }
    cc->EvalRotateKeyGen(sk, rotationFactors);

    cout << "CKKS scheme set up (depth = " << multDepth << ", batch size = " << batchSize << ")" << endl;

    Client *client = new Client(cc, pk, sk, VECTOR_DIM, "");
    Server *server = new Server(cc, pk, VECTOR_DIM);

    cout << "\n Loading Database" << endl;
    std::vector<std::string> database = readStringsFromFile(database_file);
    cout << "Loaded " << database.size() << " database entries" << endl;
    
    for (size_t i = 0; i < min(size_t(5), database.size()); i++) {
        cout << "  [" << i << "] " << database[i] << endl;
    }

    // ===== PIR =====

    vector<vector<int>> binaryDatabase;
    for (const auto& entry : database) {
        binaryDatabase.push_back(stringToBinaryVector(entry));
    }
    cout << "Converted " << binaryDatabase.size() << " entries to binary (" 
         << binaryDatabase[0].size() << " bits each)" << endl;

    server->loadAndEncryptBinaryDatabase(binaryDatabase);


    int targetIndex = 2;
    if (targetIndex < database.size()) {
        cout << "\nTesting PIR for index " << targetIndex << ": \"" << database[targetIndex] << "\"" << endl;
        
        vector<double> oneHot(batchSize, 0.0);
        oneHot[targetIndex] = 1.0;
        Ciphertext<DCRTPoly> query = OpenFHEWrapper::encryptFromVector(cc, pk, oneHot);
        server->setCiphertext(query);
        
        if (server->databaseQuery()) {
            server->saveResult();
            
            auto encryptedResults = server->getQueryResult();
            
            int bitsPerItem = binaryDatabase[0].size();
            vector<int> retrievedBits;
            
            for (int bitIdx = 0; bitIdx < bitsPerItem; bitIdx++) {
                int resultIdx = targetIndex * bitsPerItem + bitIdx;
                if (resultIdx < encryptedResults.size()) {
                    auto dec = OpenFHEWrapper::decryptToVector(cc, sk, encryptedResults[resultIdx]);
                    int bit = static_cast<int>(round(dec[0]));
                    retrievedBits.push_back(bit);
                }
            }
            
            string retrievedString = binaryVectorToString(retrievedBits);
            
            cout << "  Expected: \"" << database[targetIndex] << "\"" << endl;
            cout << "  Retrieved: \"" << retrievedString << "\"" << endl;
            
            if (database[targetIndex] == retrievedString) {
                cout << "PIR SUCCESSFUL!" << endl;
            } else {
                cout << "PIR FAILED!" << endl;
            }
        }
    }


    
    // Query
    std::vector<float> query_embedding = readFloatsFromFile(embedding_file);
    faiss::Index* index = readFaissIndex(faiss_file);

    std::cout << "Index loaded successfully!" << std::endl;
    std::cout << "Number of vectors: " << index->ntotal << std::endl;
    std::cout << "Dimension: " << index->d << std::endl;
    std::cout << "Is trained: " << (index->is_trained ? "yes" : "no") << std::endl;

    std::vector<std::vector<float>> embedding_database = faissIndexToVectors(index);

    float square_query_embedding = square(query_embedding);

    size_t db_size = embedding_database.size();
    std::vector<float> square_embedding_database(db_size);
    for (size_t i = 0; i < db_size; i++){
        square_embedding_database[i] = square(embedding_database[i]);
    }

    // Calculate similarity
    std::vector<float> distances(db_size);
    for (size_t i = 0; i < db_size; i++){
        distances[i] = euclideanDistance(
                query_embedding, embedding_database[i],
                square_query_embedding, square_embedding_database[i]);
    }

    threshold(distances, 0.61);

    // Naive-PIR retrieval
    vector<float> solutions;
    vector<string> result(db_size);
    for (size_t i = 0; i < db_size; i++){
        if (distances[i] == 1){
            result[i] = database[i];
            solutions.push_back(i);
        }
        else{
            result[i] = "0";
        }
    }

    cout << "Number of solutions " << solutions.size() << " : " << solutions << endl;
    cout << result << endl;

    // Baseline FAISS search
    int k = 10;
    std::vector<float> query(index->d);
    std::vector<float> top_distances(k);
    std::vector<faiss::idx_t> labels(k);

    index->search(1, query.data(), k, top_distances.data(), labels.data());

    std::cout << "\nTop " << k << " nearest neighbors:" << std::endl;
    for (int i = 0; i < k; ++i) {
        std::cout << "  ID: " << labels[i] << " " << database[labels[i]] << std::endl;
    }

    return 0;
}