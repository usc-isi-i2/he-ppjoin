import nltk
import csv

def bigram_tokenize(file_to_read, file_to_write):


  with open(file_to_read, newline='\n') as read:
      reader = csv.reader(read);
      for row in reader:
        token = row[0]
        spaced = ' '
        for c in token:
          spaced = spaced + c + ' '
        tokenized = spaced.split(" ")
        bigrams = list(nltk.bigrams(tokenized))
        print(bigrams)
        
        ret = []
        for b in bigrams:
          # if (b[0] == ''):
          #   new_b = (' ', b[1])
          # elif (b[1] == ''):
          #   new_b = (b[0], ' ')
          # else:
          #   new_b = b
          ret.append(''.join(b))
        
        with open(file_to_write, 'a') as write:
          writer = csv.writer(write, delimiter=",")
          writer.writerow(ret)
        write.close()
  read.close()
          



bigram_tokenize('p1_records.csv', 'p1_tokens.txt')
bigram_tokenize('p2_records.csv', 'p2_tokens.txt')