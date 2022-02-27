#include "palisade.h"
#include "csvstream.h"
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <math.h> 
#include <stdio.h>
#include <string.h>

using namespace std;
using namespace lbcrypto;

//cite: https://www.techiedelight.com/split-string-cpp-using-delimiter/
void tokenize(std::string const &str, const char delim, std::vector<int> &out) {
    size_t start;
    size_t end = 0;
 
    while ((start = str.find_first_not_of(delim, end)) != std::string::npos)
    {
        end = str.find(delim, start);
        out.push_back(stoi(str.substr(start, end - start)));
    }
}

vector<vector<int>> read_in_data (string file_to_read, vector<int> &ids, int offset) {
	csvstream csvin("../test_data/" + file_to_read);
	vector<vector<int>> token_set;
	map<string, string> row;

	while (csvin >> row) {
		string id = row["id"];
		string data = row["tokens"];
		// data = data.substr(1, data.size() - 2);
		vector<int> tokens;
		ids.push_back(stoi(id) + offset);
		const char delim = ',';
		tokenize(data, delim, tokens);
		token_set.push_back(tokens);
	} 

	return token_set;
}

map<int, int> get_local_ordering_freq (CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> kp2, vector<vector<int>> tokens, map<int, Ciphertext<DCRTPoly>> &encrypted_tokens, vector<vector<Ciphertext<DCRTPoly>>> &enc_records) {
	map<int, int> freq;
	#pragma omp for
	for (int i = 0; i < tokens.size(); i++) {
		vector<Ciphertext<DCRTPoly>> rec;
		for (int j = 0; j < tokens[i].size(); j++) {

			vector<int64_t> t = {tokens[i][j]};
			Plaintext p = cc->MakePackedPlaintext(t);
			Ciphertext<DCRTPoly> c = cc->Encrypt(kp2.publicKey, p);
			rec.push_back(c);
			encrypted_tokens[tokens[i][j]] = c;

			if (freq.find(tokens[i][j]) == freq.end()) {
				freq[tokens[i][j]] = 1;
			} else {
				freq[tokens[i][j]] ++;
			}
		}

		enc_records.push_back(rec);
	}

	return freq;

}


bool sort_enc_pairs (pair<Ciphertext<DCRTPoly>, int> &a, pair<Ciphertext<DCRTPoly>, int> &b) {
	return (a.second < b.second);
}

vector<pair<Ciphertext<DCRTPoly>, int>> encrypt_local_freq (CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> kp2, map<int, int> freq, map<int, Ciphertext<DCRTPoly>> enc_map) {
	vector<pair<Ciphertext<DCRTPoly>, int>> enc_freq;

	map<int, int>::iterator it;
	for (it = freq.begin(); it != freq.end(); it++) {
		Ciphertext<DCRTPoly> c = enc_map[it->first];
		pair<Ciphertext<DCRTPoly>, int> enc;
		enc = make_pair (c, it->second);
		enc_freq.push_back(enc);
	}

	sort(enc_freq.begin(), enc_freq.end(), sort_enc_pairs);

	return enc_freq;
}

bool is_a_match (CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> kpMultiparty, Plaintext decryptResult, Ciphertext<DCRTPoly> cipher) {
    cc->Decrypt(kpMultiparty.secretKey, cipher, &decryptResult);
    if (decryptResult->GetPackedValue()[0] == 0) {
    	return true;
    } else {
    	return false;
    }
    
}

int private_set_intersection (CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> kpMultiparty, vector<Ciphertext<DCRTPoly>> x, vector<Ciphertext<DCRTPoly>> y) {
	int _x_= x.size();
	int _y_ = y.size(); 

	Plaintext decryptResult;
	int count = 0;
	#pragma omp for
	for (int i = 0; i < _x_; i++) {
		for (int j = 0; j < _y_; j++) {
			auto sub = cc->EvalSub(x[i], y[j]);
			if (is_a_match(cc, kpMultiparty, decryptResult, sub)) {
				count += 1;
			}
		}
	}

	return count;

}

vector<pair<Ciphertext<DCRTPoly>, int>> doc_freq_join (CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> kpMultiparty, vector<pair<Ciphertext<DCRTPoly>, int>> enc_freq1, vector<pair<Ciphertext<DCRTPoly>, int>> enc_freq2) {
	vector<pair<Ciphertext<DCRTPoly>, int>> doc_freq;
	set<int> idx;
	set<int> jdx;

	#pragma omp for
	for (int i = 0; i < enc_freq1.size(); ++i) 
    	idx.insert(idx.end(), i);

  #pragma omp for
	for (int j = 0; j < enc_freq2.size(); ++j) 
		jdx.insert(jdx.end(), j);

  #pragma omp for
	for (int i = 0; i < enc_freq1.size(); i++) {
		for (int j = 0; j < enc_freq2.size(); j++) {
			pair<Ciphertext<DCRTPoly>, int> p1 = enc_freq1[i];
			pair<Ciphertext<DCRTPoly>, int> p2 = enc_freq2[j];

			auto sub = cc->EvalSub(p1.first, p2.first);
			Plaintext decryptResult;
			if (is_a_match(cc, kpMultiparty, decryptResult, sub)) {
				pair<Ciphertext<DCRTPoly>, int> pjoin = make_pair(p1.first, (p1.second + p2.second));
				idx.erase(i);
				jdx.erase(j);
				doc_freq.push_back(pjoin);
			} 
		}
	}

	for (auto i : idx) {
		doc_freq.push_back(enc_freq1[i]);
	}

	for (auto j : jdx) {
		doc_freq.push_back(enc_freq2[j]);
	}

	sort(doc_freq.begin(), doc_freq.end(), sort_enc_pairs);

	return doc_freq;

}

int get_token_pos (CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> kpMultiparty, vector<pair<Ciphertext<DCRTPoly>, int>> map, Ciphertext<DCRTPoly> c) {
	for (int i = 0; i < map.size(); i++) {
		auto sub = cc->EvalSub(map[i].first, c);
		Plaintext decryptResult;
		if (is_a_match(cc, kpMultiparty, decryptResult, sub)) {
			return i;
		}
	}

	return -1;
}

bool compareRecs(pair<Ciphertext<DCRTPoly>, int> p1, pair<Ciphertext<DCRTPoly>, int> p2) {
    return (p1.second < p2.second);
}

void sort_rec (vector<pair<Ciphertext<DCRTPoly>, int>> &rec) {
	sort(rec.begin(), rec.end(), compareRecs);
}

void sort_global (vector<pair<vector<Ciphertext<DCRTPoly>>, int>> &global, map<int, int> &rid_mapping) {
	#pragma omp for 
	for (int idx = 0; idx < global.size(); idx++) {
		int min = 0;
		for (int jdx = 1; jdx < global.size(); jdx++) {
			if (global[min].second > global[jdx].second) {
				min = jdx;
			}
		}
		rid_mapping[idx] = min;
		global[min].second = INT_MAX;
	}

}


CryptoContext<DCRTPoly> gen_crypto_context (int plaintextModulus, double sigma, int depth) {

	// Instantiate the BGVrns crypto context
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          depth, plaintextModulus, HEStd_128_classic, sigma, depth, OPTIMIZED, BV);

  // enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(MULTIPARTY);

	return cc;

}

void gen_multiparty_keys (CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> kp1, LPKeyPair<DCRTPoly> kp2, LPKeyPair<DCRTPoly> kpMultiparty) {

		 cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(
    	cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));


    auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys,
                                             kp2.publicKey->GetKeyTag());

    auto evalSumKeysJoin = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB,
                                                 kp2.publicKey->GetKeyTag());

    cc->InsertEvalSumKey(evalSumKeysJoin);
}











