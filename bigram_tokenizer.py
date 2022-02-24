import csv, sys

def qgram_tokenizer(n, s, place_holder=' ', padded=False):
    if len(s) == 0:
        return []
    if padded:
        pad = place_holder * (n - 1)
        s = pad + s + pad
    s = s.split(' ')
    s = place_holder.join(s)
    if len(s) < n:
        return [s]
    return [s[i:i + n] for i in range(len(s) - n + 1)]


def tokenizer(n, record):
    return set(qgram_tokenizer(n, record.lower()))


def tokenize(file_to_read, file_to_write):
  ids = []
  tokens = []
  with open(file_to_read, encoding='latin-1', newline='\n') as read:
      reader = csv.reader(read);
      line_count = 0
      for row in reader:
        if line_count != 0:
            qgrams = tokenizer(2, row[1])
            encoded = {encode_token(t) for t in qgrams}
            tokens.append(encoded)
            ids.append(row[0])
        line_count+=1
  fw =  open(file_to_write, 'w+')
  csv_writer = csv.writer(fw, delimiter=",")
  csv_writer.writerow(["id", "tokens"])
  csv_writer.writerows(zip(ids, tokens))
  fw.close()
  read.close()
          


def encode_token(t):
    if len(t) >= 8:
        raise ValueError('Max length of character is 8')

    re = 0
    for idx, c in enumerate(reversed(t)):
        re += (ord(c) & 0xff) << (8 * idx)
    return re

p1_records = sys.argv[1]
p2_records = sys.argv[2]
p1_tokens = sys.argv[3]
p2_tokens = sys.argv[4]

tokenize(p1_records, p1_tokens)
tokenize(p2_records, p2_tokens)