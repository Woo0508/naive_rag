#ifndef CSV_READER_H
#define CSV_READER_H

#include <string>
#include <vector>
#include <fstream>
#include <iostream>

using namespace std;






static vector<vector<int>> readBinaryStringCSV(const string& filename) {
    vector<vector<int>> binaryData;
    ifstream file(filename);
    
    if (!file.is_open()) {
        cerr << "Error: could not open file " << filename << endl;
        return binaryData;
    }
    
    string line;
    int lineNum = 0;
    while (getline(file, line)) {
        lineNum++;
        if (line.empty()) continue;
        
        size_t start = line.find_first_not_of(" \t\r\n");
        size_t end = line.find_last_not_of(" \t\r\n");
        if (start == string::npos) continue;
        line = line.substr(start, end - start + 1);
        


        vector<int> binaryVector;
        for (char c : line) {
            if (c == '0') {
                binaryVector.push_back(0);
            } else if (c == '1') {
                binaryVector.push_back(1);
            } else {
                continue;
            }
        }
        
        if (!binaryVector.empty()) {
            binaryData.push_back(binaryVector);
            if (binaryData.size() <= 5) {
                cout << "  Line " << lineNum << ": " << line << " -> [";
                for (size_t i = 0; i < min(size_t(10), binaryVector.size()); i++) {
                    cout << binaryVector[i];
                }
                if (binaryVector.size() > 10) cout << "...";
                cout << "] (" << binaryVector.size() << " bits)" << endl;
            }
        }
    }
    
    file.close();
    cout << "loaded " << binaryData.size() << " binary strings from " << filename << endl;
    return binaryData;
}

#endif
