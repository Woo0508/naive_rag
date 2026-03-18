// General functionality header files
#include "include/config.h"
#include "include/vector_utils.h"
#include "include/openFHE_wrapper.h"
#include "openfhe.h"
#include <iostream>
#include <ctime>

#include "utils.cpp"
#include "include/client.h"
#include "include/server.h"

using namespace lbcrypto;
using namespace std;
using namespace VectorUtils;

// new
// TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
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
    /**

    //Setup Client and Server
    size_t multDepth = OpenFHEWrapper::computeRequiredDepth(5);

    // Declare CKKS scheme elements
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
    // generate keys from 1 to VECTOR_DIM
    iota(rotationFactors.begin(), rotationFactors.end(), 1);
    // generate positive binary rotation keys greater than VECTOR_DIM
    for(int i = VECTOR_DIM; i < int(batchSize); i *= 2) {
        rotationFactors.push_back(i);
    }
    // generate negative binary rotation keys
    for(int i = 1; i < int(batchSize); i *= 2) {
        rotationFactors.push_back(-i);
    }
    cc->EvalRotateKeyGen(sk, rotationFactors);

    cout << "CKKS scheme set up (depth = " << multDepth << ", batch size = " << batchSize << ")" << endl;

    Client *client = new Client(cc, pk, sk, 528);
    Server *server = new Server(cc, pk, 528);
     **/

    //Query
    std::vector<float> query_embedding = readFloatsFromFile(embedding_file);
    std::vector<std::string> database = readStringsFromFile(database_file);
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

    //Calculate similarity
    std::vector<float> distances(db_size);
    for (size_t i = 0; i < db_size; i++){
        distances[i] = euclideanDistance(
                query_embedding,embedding_database[i],
                square_query_embedding,square_embedding_database[i]);
    }
    cout << distances << endl;

    threshold(distances, 0.61);
    cout << distances << endl;

    //Multiply by database
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

    //Decode result
    cout << "Number of solutions " << solutions.size() << " : " << solutions << endl;
    cout << result << endl;

    //Baseline
    int k = 10;  // number of nearest neighbors
    std::vector<float> query(index->d);  // query vector
    // Fill query vector with your data...

    std::vector<float> top_distances(k);
    std::vector<faiss::idx_t> labels(k);

    index->search(1, query.data(), k, top_distances.data(), labels.data());

    std::cout << "\nTop " << k << " nearest neighbors:" << std::endl;
    for (int i = 0; i < k; ++i) {
        std::cout << "  ID: " << labels[i] << " " << database[labels[i]] << std::endl;
        // Distance: " << distances[i] << std::endl;

    }

    return 0;
}

// TIP See CLion help at <a
// href="https://www.jetbrains.com/help/clion/">jetbrains.com/help/clion/</a>.
//  Also, you can try interactive lessons for CLion by selecting
//  'Help | Learn IDE Features' from the main menu.