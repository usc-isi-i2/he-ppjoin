#include "palisade.h"
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <math.h> 

using namespace std;
using namespace lbcrypto;

vector<vector<string>> format_bigrams (string file_to_read) {
	ifstream file ("../heppjoin/" + file_to_read, ios::out);
	vector<vector<string>> bigrams;

	if (file.is_open()) {
		string line = "";
		while (getline(file, line, '\n')) {
			stringstream ss(line);
			vector<string> result;
			int idx = 0;
			while (ss.good()) {
				string substr;
				getline(ss, substr, ',');

				if (substr.length() == 1) {
					if (idx == 0) {
						substr = " " + substr;
					} else {
						substr = substr + " ";
					}
				}
				result.push_back(substr);
				idx++;
			}
			bigrams.push_back(result);
		}

	} 

	return bigrams;
}

int convert_to_ascii (string str) {
	stringstream ss;
	for (int i = 0; i < str.length(); i++) {
		char c = str.at(i);
		ss << hex << int(c);
	}

	int x;
	ss >> x;
	return x;
}

map<string, int> get_local_ordering_freq (CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> kp2, vector<vector<string>> tokens, map<string, Ciphertext<DCRTPoly>> &encrypted_tokens, vector<vector<Ciphertext<DCRTPoly>>> &enc_records) {
	map<string, int> freq;

	for (int i = 0; i < tokens.size(); i++) {
		vector<Ciphertext<DCRTPoly>> rec;
		for (int j = 0; j < tokens[i].size(); j++) {

			vector<double> t = {(double) convert_to_ascii(tokens[i][j])};
			Plaintext p = cc->MakeCKKSPackedPlaintext(t);
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

vector<pair<Ciphertext<DCRTPoly>, int>> encrypt_local_freq (CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> kp2, map<string, int> freq, map<string, Ciphertext<DCRTPoly>> enc_map) {
	vector<pair<Ciphertext<DCRTPoly>, int>> enc_freq;

	map<string, int>::iterator it;
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
    if (decryptResult->GetCKKSPackedValue()[0].real() <= 0.0005 &&
          decryptResult->GetCKKSPackedValue()[0].real() >= -0.0005) {
    	return true;
    } else {
    	return false;
    }
    
}

vector<pair<Ciphertext<DCRTPoly>, int>> doc_freq_join (CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> kpMultiparty, vector<pair<Ciphertext<DCRTPoly>, int>> enc_freq1, vector<pair<Ciphertext<DCRTPoly>, int>> enc_freq2) {
	vector<pair<Ciphertext<DCRTPoly>, int>> doc_freq;
	set<int> idx;
	set<int> jdx;

	for (int i = 0; i < enc_freq1.size(); ++i) 
    idx.insert(idx.end(), i);

  for (int j = 0; j < enc_freq2.size(); ++j) 
  	jdx.insert(jdx.end(), j);

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

vector<int> get_prefix_lengths (vector<vector<Ciphertext<DCRTPoly>>> global_enc_recs, double t) {
	vector<int> prefixes;
	for (int i = 0; i < global_enc_recs.size(); i++) {
		int x = global_enc_recs[i].size();
		double temp = ceil((1 - t) * x);
		int pref = int(temp + 1);
		prefixes.push_back(pref);
	}

	return prefixes;
}


int get_token_count (CryptoContext<DCRTPoly> cc, LPKeyPair<DCRTPoly> kpMultiparty, vector<pair<Ciphertext<DCRTPoly>, int>> map, Ciphertext<DCRTPoly> c) {

	for (int i = 0; i < map.size(); i++) {
		auto sub = cc->EvalSub(map[i].first, c);
		Plaintext decryptResult;
		if (is_a_match(cc, kpMultiparty, decryptResult, sub)) {
			return map[i].second;
		}
	}

	return -1;
}

bool compareRecs(pair<Ciphertext<DCRTPoly>, int> p1, pair<Ciphertext<DCRTPoly>, int> p2) {
    return (p1.second <= p2.second);
}

bool compareGlobal(pair<vector<Ciphertext<DCRTPoly>>, int> p1, pair<vector<Ciphertext<DCRTPoly>>, int> p2) {
    return (p1.second <= p2.second);
}

void sort_rec (vector<pair<Ciphertext<DCRTPoly>, int>> &rec) {
	sort(rec.begin(), rec.end(), compareRecs);
}

void sort_global (vector<pair<vector<Ciphertext<DCRTPoly>>, int>> &global) {
	sort(global.begin(), global.end(), compareGlobal);
}


CryptoContext<DCRTPoly> gen_crypto_context (int init_size, int dcrtBits, int batch_size) {

	CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          init_size - 1, dcrtBits, batch_size, HEStd_128_classic,
          0,                    /*ringDimension*/
          APPROXRESCALE, BV, 1, /*numLargeDigits*/
          1,                    /*maxDepth*/
          60,                   /*firstMod*/
          5, OPTIMIZED);

	  // enable features that you wish to use
	  cc->Enable(ENCRYPTION);
	  cc->Enable(SHE);
	  cc->Enable(LEVELEDSHE);
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











