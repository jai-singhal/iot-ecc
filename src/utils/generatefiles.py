import nltk.corpus as corpus
import nltk
from nltk.corpus import conll2000, conll2002

# nltk.download('conll2000')
# nltk.download('conll2002')

data = ""
for sent in conll2000.sents():
    sentence = ""
    for word in sent:
        try:
            sentence = sentence + str(word) + " "
        except:
            continue
    data = data + sentence + "\n"

for sent in conll2002.sents():
    sentence = ""
    for word in sent:
        try:
            sentence = sentence + str(word) + " "
        except:
            continue
    data = data + sentence + "\n"

total_len = len(data)

filesizes = [200, 400, 500]
pvsdataptr = 0
for filesize in filesizes:
    filename = "../data/conll_{}kB.txt".format(filesize)
    with open(filename, "wb") as fout:
        if pvsdataptr + filesize*1000 > total_len:
            pvsdataptr = 0
        fout.write(data[pvsdataptr:filesize*1000])
        pvsdataptr = filesize*1000

