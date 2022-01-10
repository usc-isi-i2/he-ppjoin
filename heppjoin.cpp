#include "palisade.h"
#include "utility.h"

double t = 0.8; //global var --> similarity threshold

//true if passes length filter check, false otherwise
bool length_filter (int x, int y) {
	if (x < ceil(t * y)) { //don't compare x against y + longer recs
		return false;
	} else {
		return true;
	}
}

//true if passes prefix filter check, false otherwise
bool prefix_filter (int x, int y, int overlap) {
	if (overlap >= ceil((t / 1 + t) * (x + y))) { //overlap greater, should compare x with y
		return true;
	} else {
		return false;
	}
}

int main(int argc, char** argv) {

	auto start = std::chrono::high_resolution_clock::now();
	cout << "- gen crypto context (1)" << endl;
	int init_size = 1;
	int dcrtBits = 40;
	int batch_size = 16;

	CryptoContext<DCRTPoly> cc = gen_crypto_context(init_size, dcrtBits, batch_size);

	LPKeyPair<DCRTPoly> kp1;
 	LPKeyPair<DCRTPoly> kp2;

  	LPKeyPair<DCRTPoly> kpMultiparty;

  	kp1 = cc->KeyGen();
  	kp2 = cc->MultipartyKeyGen(kp1.publicKey);
  	vector<LPPrivateKey<DCRTPoly>> secretKeys;
  	secretKeys.push_back(kp1.secretKey);
  	secretKeys.push_back(kp2.secretKey);
  	kpMultiparty = cc->MultipartyKeyGen(secretKeys);
  	gen_multiparty_keys(cc, kp1, kp2, kpMultiparty);

  	auto stop = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = stop - start;
    cout << duration.count() << endl;

	start = std::chrono::high_resolution_clock::now();
  	cout << "- local bigram tokenization + local doc freq (2)" << endl;
	vector<vector<string>> p1 = format_bigrams ("p1_tokens.txt");
	vector<vector<Ciphertext<DCRTPoly>>>  p1_enc_recs;

	vector<vector<string>> p2 = format_bigrams ("p2_tokens.txt");
	vector<vector<Ciphertext<DCRTPoly>>>  p2_enc_recs;

	map<string, Ciphertext<DCRTPoly>> p1_enc_map;
	map<string, Ciphertext<DCRTPoly>> p2_enc_map;

	map<string, int> p1_local_freq = get_local_ordering_freq (cc, kp2, p1, p1_enc_map, p1_enc_recs);
	vector<pair<Ciphertext<DCRTPoly>, int>> p1_enc_freq = encrypt_local_freq (cc, kp2, p1_local_freq, p1_enc_map);

	map<string, int> p2_local_freq = get_local_ordering_freq (cc, kp2, p2, p2_enc_map, p2_enc_recs);
	vector<pair<Ciphertext<DCRTPoly>, int>> p2_enc_freq = encrypt_local_freq (cc, kp2, p2_local_freq, p2_enc_map);

	cout << "P1 local enc doc. freq map: " << endl;
	for (int i = 0; i < p1_enc_freq.size(); i++) {
		 Plaintext decryptResult;
      	 cc->Decrypt(kpMultiparty.secretKey, p1_enc_freq[i].first, &decryptResult);
      	 cout << decryptResult->GetCKKSPackedValue()[0].real() << ": " << p1_enc_freq[i].second << endl;
	}

	cout << "P2 local enc doc. freq map: " << endl;
	for (int i = 0; i < p2_enc_freq.size(); i++) {
		Plaintext decryptResult;
      	cc->Decrypt(kpMultiparty.secretKey, p2_enc_freq[i].first, &decryptResult);
      	cout << decryptResult->GetCKKSPackedValue()[0].real() << ": " << p2_enc_freq[i].second << endl;
	}

	stop = std::chrono::high_resolution_clock::now();
    duration = stop - start;
    cout << duration.count() << endl;

    start = std::chrono::high_resolution_clock::now();
	cout << "- coalescing doc freq on third party (3)" << endl;
	vector<pair<Ciphertext<DCRTPoly>, int>> global_enc_freq = doc_freq_join (cc, kpMultiparty, p1_enc_freq, p2_enc_freq);

	cout << "Global doc. freq map: " << endl;
	for (int i = 0; i < global_enc_freq.size(); i++) {
		Plaintext decryptResult;
      	cc->Decrypt(kpMultiparty.secretKey, global_enc_freq[i].first, &decryptResult);
      	cout << decryptResult->GetCKKSPackedValue()[0].real() << ": " << global_enc_freq[i].second << endl;
	}

	stop = std::chrono::high_resolution_clock::now();
    duration = stop - start;
    cout << duration.count() << endl;

    start = std::chrono::high_resolution_clock::now();
	cout << "- reordering global doc freq table (4)" << endl;
	map<int, vector<Ciphertext<DCRTPoly>>> id_mapping;

	vector<vector<Ciphertext<DCRTPoly>>> global_enc_recs = p1_enc_recs;
	global_enc_recs.insert(global_enc_recs.end(), p2_enc_recs.begin(), p2_enc_recs.end());

	for (int i = 0; i < global_enc_recs.size(); i++) {
		vector<pair<Ciphertext<DCRTPoly>, int>> counts;
		for (int j = 0; j < global_enc_recs[i].size(); j++) {
			int count = get_token_count(cc, kpMultiparty, global_enc_freq, global_enc_recs[i][j]);
			counts.push_back(make_pair(global_enc_recs[i][j], count));
		}

		sort_rec(counts);

		for (int k = 0; k < counts.size(); k++) {
			global_enc_recs[i][k] = counts[k].first;
		}

		id_mapping[i] = global_enc_recs[i];
	}

	stop = std::chrono::high_resolution_clock::now();
    duration = stop - start;
    cout << duration.count() << endl;

    start = std::chrono::high_resolution_clock::now();
	cout << "- calculating prefix lengths (5)" << endl;
	vector<int> prefixes = get_prefix_lengths(global_enc_recs, t);
	cout << prefixes << endl;

	map<vector<Ciphertext<DCRTPoly>>, int> pref_to_id;
	map<int, vector<Ciphertext<DCRTPoly>>> id_to_pref;
	for (int k = 0; k < global_enc_recs.size(); k++) {
		vector<Ciphertext<DCRTPoly>> prefix = {global_enc_recs[k].begin(), global_enc_recs[k].begin() + prefixes[k]};
		pref_to_id[prefix] = k;
		id_to_pref[k] = prefix;
	}

	stop = std::chrono::high_resolution_clock::now();
    duration = stop - start;
    cout << duration.count() << endl;

    start = std::chrono::high_resolution_clock::now();
	cout << "- sorting records by length (6)" << endl;
	vector<pair<vector<Ciphertext<DCRTPoly>>, int>> lengths;
	for (int i = 0; i < global_enc_recs.size(); i++) {
		lengths.push_back(make_pair(global_enc_recs[i], global_enc_recs[i].size()));
	}

	sort_global(lengths);
	for (int j = 0; j < global_enc_recs.size(); j++) {
		global_enc_recs[j] = lengths[j].first;
		cout << global_enc_recs[j].size() << endl;
	}

	stop = std::chrono::high_resolution_clock::now();
    duration = stop - start;
    cout << duration.count() << endl;


    start = std::chrono::high_resolution_clock::now();
	cout << "- inverted index creation + filtering (7)" << endl;
	vector<vector<int>> matches;
	map<vector<int>, int> overlaps;
	map<Ciphertext<DCRTPoly>, vector<int>> inverted_index;
	for (int i = 0; i < global_enc_recs.size(); i++) {
		//cout << "checking length filter for rec id: " << i << endl;
		if (length_filter(global_enc_recs[i].size(), global_enc_recs[i+1].size()) && i != global_enc_recs.size() - 1) {
			//cout << "length filter for rec id: " << i << " passed" << endl;

			for (Ciphertext<DCRTPoly> c: id_to_pref[i]) {
				vector<int> tokens;
				for (const auto &myPair : inverted_index) {
					Ciphertext<DCRTPoly> key = myPair.first;
	        		auto match = cc->EvalSub(c, key);
	        		Plaintext decryptResult;
	        		if (is_a_match(cc, kpMultiparty, decryptResult, match)) {
	        			tokens = inverted_index[key];
	        			tokens.push_back(i);
	        			matches.push_back(tokens);

	        			int curr_overlap = overlaps[tokens];
	        			curr_overlap++;
	        			overlaps[tokens] = curr_overlap;
	        			inverted_index[key] = tokens;

	        			// cout << tokens << endl;
	        			// cout << curr_overlap << endl;
	        		} 
	    		}
	    		tokens = {i};
	    		overlaps[tokens] = 1;
	    		inverted_index[c] = tokens;

			}
		}
	}

	for (int i = 0; i < matches.size(); i++) {
		vector<int> match = matches[i];
		if (!prefix_filter(id_mapping[match[0]].size(), id_mapping[match[1]].size(), overlaps[match])) {
			matches.erase(matches.begin() + i);
		}
	}

	cout << matches << endl;

	stop = std::chrono::high_resolution_clock::now();
    duration = stop - start;
    cout << duration.count() << endl;
}
