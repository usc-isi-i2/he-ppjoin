#include "palisade.h"
#include "utility.h"

double t = 0.5; //global var --> similarity threshold

int main(int argc, char** argv) {

	auto start = std::chrono::high_resolution_clock::now();
	cout << "- local pre-processing" << endl;

	int plaintextModulus = 65537;
	double sigma = 3.2;
	int depth = 1;

	CryptoContext<DCRTPoly> cc = gen_crypto_context(plaintextModulus, sigma, depth);

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

  	vector<int> p1_ids;
	vector<vector<int>> p1 = read_in_data ("ds1_100_0.5.csv", p1_ids, 0);
	vector<vector<Ciphertext<DCRTPoly>>>  p1_enc_recs;

	vector<int> p2_ids;
	vector<vector<int>> p2 = read_in_data ("ds2_100_0.5.csv", p2_ids, p1_ids.size());
	vector<vector<Ciphertext<DCRTPoly>>>  p2_enc_recs;

	vector<int> p_ids = p1_ids;
	p_ids.insert(p_ids.end(), p2_ids.begin(), p2_ids.end());

	map<int, int> pid_check;

	for (int id: p1_ids) {
		pid_check[id] = 1;
	}
	for (int id: p2_ids) {
		pid_check[id] = 2;
	}

	map<int, Ciphertext<DCRTPoly>> p1_enc_map;
	map<int, Ciphertext<DCRTPoly>> p2_enc_map;

	map<int, int> p1_local_freq = get_local_ordering_freq (cc, kp2, p1, p1_enc_map, p1_enc_recs);
	vector<pair<Ciphertext<DCRTPoly>, int>> p1_enc_freq = encrypt_local_freq (cc, kp2, p1_local_freq, p1_enc_map);

	map<int, int> p2_local_freq = get_local_ordering_freq (cc, kp2, p2, p2_enc_map, p2_enc_recs);
	vector<pair<Ciphertext<DCRTPoly>, int>> p2_enc_freq = encrypt_local_freq (cc, kp2, p2_local_freq, p2_enc_map);

	auto stop = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = stop - start;
    cout << duration.count()  << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();
	cout << "- global pre-processing" << endl;
	vector<pair<Ciphertext<DCRTPoly>, int>> global_enc_freq = doc_freq_join (cc, kpMultiparty, p1_enc_freq, p2_enc_freq);

	map<int, vector<Ciphertext<DCRTPoly>>> id_mapping;

	vector<vector<Ciphertext<DCRTPoly>>> global_enc_recs = p1_enc_recs;
	global_enc_recs.insert(global_enc_recs.end(), p2_enc_recs.begin(), p2_enc_recs.end());

	for (int i = 0; i < global_enc_recs.size(); i++) {
		vector<pair<Ciphertext<DCRTPoly>, int>> positions;
		for (int j = 0; j < global_enc_recs[i].size(); j++) {
			int pos = get_token_pos(cc, kpMultiparty, global_enc_freq, global_enc_recs[i][j]);
			positions.push_back(make_pair(global_enc_recs[i][j], pos));
		}

		sort_rec(positions);

		for (int k = 0; k < positions.size(); k++) {
			global_enc_recs[i][k] = positions[k].first;
		}

		id_mapping[i] = global_enc_recs[i];
	}

	vector<pair<vector<Ciphertext<DCRTPoly>>, int>> lengths;
	for (int i = 0; i < global_enc_recs.size(); i++) {
		lengths.push_back(make_pair(global_enc_recs[i], global_enc_recs[i].size()));
	}
	map<int, int> rid_mapping;
	sort_global(lengths, rid_mapping);

	stop = std::chrono::high_resolution_clock::now();
    duration = stop - start;
    cout << duration.count() << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();
	cout << "- he-ppjoin + he-verify" << endl;
	set<pair<int, int>> matches;
	map<Ciphertext<DCRTPoly>, set<pair<int, int>>> inverted_index;

	#pragma omp for
	for (int idx = 0; idx < rid_mapping.size(); idx++) {
		int rid_x = rid_mapping[idx];
		vector<Ciphertext<DCRTPoly>> x = id_mapping[rid_x];
		map<int, int> A;
		int _x_ = x.size();
		int xp = _x_ - ceil(t * _x_) + 1;

		for (int i = 0; i < xp; i++) {
			Ciphertext<DCRTPoly> w = x[i];
			//need to check w against all keys in ii
			for (auto &ii: inverted_index) {
				Ciphertext<DCRTPoly> key = ii.first;
				auto match = cc->EvalSub(w, key);
        		Plaintext decryptResult;
        		if (is_a_match(cc, kpMultiparty, decryptResult, match)) {
        			set<pair<int, int>> ids = inverted_index[key];
        			for (auto pair: ids) {
						int rid_y = pair.first;

						//added filter to check if same data owner
						bool same_owner = pid_check[p_ids[rid_x]] == pid_check[p_ids[rid_y]];
						if (same_owner) {
							continue;
						}

						int j = pair.second;

						int _y_ = id_mapping[rid_y].size();

						if (_y_ < (t * _x_)) {
							continue;
						}

						int alpha = ceil((t / (1 + t) * (_x_ + _y_)));
						int ubound = 1 + min(_x_ - i, _y_ - j);

						//cout << A[rid_y] << ", " << "alpha: " << alpha << ", ubound: " << ubound << endl;

						if (A[rid_y] + ubound >= alpha) {
							A[rid_y] += 1;
						} else {
							A[rid_y] = 0;
						}

					}
        		}

			}

			set<pair<int, int>> get = inverted_index[w];
			get.insert(make_pair(rid_x, i));
			inverted_index[w] = get;
		}

		for (auto const& pair : A) {
			int rid_y = pair.first;
			int overlap = pair.second;
			vector<Ciphertext<DCRTPoly>> y = id_mapping[rid_y];
			int _y_ = y.size();
			int yp = _y_ - ceil(t * _y_) + 1;

			Ciphertext<DCRTPoly> wx = x[xp - 1];
			Ciphertext<DCRTPoly> wy = y[yp - 1];


			int alpha = ceil((t / (1 + t) * (_x_ + _y_)));

			// cout << "comparing rid_x: " << rid_x << ", rid_y: " << rid_y << endl;
			// cout << "_x_: " << _x_ << ", _y_: " <<  _y_ << endl;
			// cout << "overlap: " << overlap << ", alpha: " << alpha << endl;  

			int rest = 0; 
			int ubound = 0;

			int wx_pos = 0;
			int wy_pos = 0;

			Plaintext decryptResult;
			for (int k = 0; k < global_enc_freq.size(); k++) {
				auto is_wx_match = cc->EvalSub(wx, global_enc_freq[k].first);
				auto is_wy_match = cc->EvalSub(wy, global_enc_freq[k].first);
				if (is_a_match(cc, kpMultiparty, decryptResult, is_wx_match)) {
					wx_pos = k;
				}

				if (is_a_match(cc, kpMultiparty, decryptResult, is_wy_match)) {
					wy_pos = k;
				}
			}

			// cout << "wx_pos: " << wx_pos << ", wy_pos: " << wy_pos << endl;

			if (wx_pos < wy_pos) {
				ubound = overlap + _x_ - xp;
				if (ubound >= alpha) {
					vector<Ciphertext<DCRTPoly>> newx = {x.begin() + (xp), x.end()};
					vector<Ciphertext<DCRTPoly>> newy = {y.begin() + (overlap), y.end()};
					rest = private_set_intersection(cc, kpMultiparty, newx, newy);
				}
			} else {
				ubound = overlap + _y_ - yp;
				if (ubound >= alpha) {
					vector<Ciphertext<DCRTPoly>> newx = {x.begin() + (overlap), x.end()};
					vector<Ciphertext<DCRTPoly>> newy = {y.begin() + (yp), y.end()};
					rest = private_set_intersection(cc, kpMultiparty, newx, newy);
				}
			}

			overlap += rest;
			if (overlap >= alpha) {
				matches.insert(make_pair(rid_x, rid_y));
			}

		}
	}

	stop = std::chrono::high_resolution_clock::now();
    duration = stop - start;
    cout << duration.count() << " ms" << endl;

	for (auto match: matches) {
		cout << "match between " << p_ids[match.first] << ", " << p_ids[match.second] << endl;
	}
}
