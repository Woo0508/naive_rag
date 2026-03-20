// General functionality header files
#include "include/config.h"
#include "include/vector_utils.h"
#include "include/openFHE_wrapper.h"
#include "openfhe.h"
#include <iostream>
#include <ctime>
#include <fstream>

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
    

    //Query
    std::vector<float> query_embedding = readFloatsFromFile(embedding_file);
    std::vector<std::string> database = readStringsFromFile(database_file);
    faiss::Index* index = readFaissIndex(faiss_file);

    std::cout << "Index loaded successfully!" << std::endl;
    std::cout << "Number of vectors: " << index->ntotal << std::endl;
    std::cout << "Dimension: " << index->d << std::endl;
    std::cout << "Is trained: " << (index->is_trained ? "yes" : "no") << std::endl;

    std::vector<std::vector<float>> embedding_database = faissIndexToVectors(index);

    // plaintext approach- 
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

    {
        std::ofstream out("plaintext_distances.txt");
        if (!out.is_open()) {
            std::cerr << "Could not open\n";
        } else {
            for (size_t i = 0; i < distances.size(); i++) {
                out << i << "," << distances[i]<< "\n";
            }
        }
    }


    //ENCRYPTED APPROACH- 

    // precompute e^2 in plaintext then encrypt it
    std::vector<double> query_embedding_d(query_embedding.begin(), query_embedding.end());

    std::vector<double> e_sq_vec(query_embedding.size());   //new vector to store squares
    for (size_t j = 0; j < query_embedding.size(); j++) {
        const double v = static_cast<double>(query_embedding[j]);
        e_sq_vec[j] = v * v;
    }

    // encrypt query embedding and squared embedding
    Plaintext ptE = cc->MakeCKKSPackedPlaintext(query_embedding_d);
    Ciphertext<DCRTPoly> ctE = cc->Encrypt(pk, ptE);

    Plaintext ptESq = cc->MakeCKKSPackedPlaintext(e_sq_vec);
    Ciphertext<DCRTPoly> ctESq = cc->Encrypt(pk, ptESq);

    // compute encrypted ||e||^2 by summing slots of e^2
    Ciphertext<DCRTPoly> ctE2 = OpenFHEWrapper::sumAllSlots(cc, ctESq);

    //size_t db_size = embedding_database.size(); 
    // TESTING
    size_t db_size = std::min<size_t>(100, embedding_database.size());
    
    
    std::vector<float> square_embedding_database(db_size);  //new vector to store squares of database
    for (size_t i = 0; i < db_size; i++){
        square_embedding_database[i] = square(embedding_database[i]);
    }

    //Calculate similarity
    std::vector<float> distances(db_size);
    // plaintext vector of -2 
    Plaintext ptMinusTwo = cc->MakeCKKSPackedPlaintext(std::vector<double>(batchSize, -2.0));

    for (size_t i = 0; i < db_size; i++) {

        // printing progress for testing
        if (i % 10 == 0) {
            std::cout << "Processing vector " << i << " / " << db_size << std::endl;
        }
        
        // encode database vectors in plaintext
        std::vector<double> d_vec_d(embedding_database[i].begin(), embedding_database[i].end());
        Plaintext ptD = cc->MakeCKKSPackedPlaintext(d_vec_d);

        // encrypted inner product <e, d>- componentwise multiply
        Ciphertext<DCRTPoly> ctED = cc->EvalMult(ctE, ptD);
        // sum all slots for inner product 
        Ciphertext<DCRTPoly> ctInner = OpenFHEWrapper::sumAllSlots(cc, ctED);

        // -2<e,d>
        Ciphertext<DCRTPoly> ctMinus2Inner = cc->EvalMult(ctInner, ptMinusTwo);

        // (||d||^2) as plaintext replicated across slots
        const double d2 = static_cast<double>(square_embedding_database[i]);
        Plaintext ptD2 = cc->MakeCKKSPackedPlaintext(std::vector<double>(batchSize, d2));

        // Distance^2 = ||d||^2 + ||e||^2 - 2<e,d>
        Ciphertext<DCRTPoly> ctDist = cc->EvalAdd(ctMinus2Inner, ctE2);
        ctDist = cc->EvalAdd(ctDist, ptD2);

        // decrypt distance
        Plaintext ptDist;
        cc->Decrypt(sk, ctDist, &ptDist);
        ptDist->SetLength(1);
        const auto vals = ptDist->GetRealPackedValue();
        distances[i] = static_cast<float>(vals.empty() ? 0.0 : vals[0]);
    }
    cout << distances << endl;

    // save distances to a file before thresholding
    {
        std::ofstream out("distances.txt");
        if (!out.is_open()) {
            std::cerr << "Could not open distances.txt for writing" << std::endl;
        } else {
            for (size_t i = 0; i < distances.size(); i++) {
                out << distances[i] << "\n";
            }
        }
    }

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