import nltk.corpus as corpus
import nltk
from nltk.corpus import conll2000, conll2002
from tqdm import tqdm
# nltk.download('conll2000')
# nltk.download('conll2002')

# data = ""
# for sent in tqdm(conll2000.sents()):
#     sentence = ""
#     for word in sent:
#         try:
#             sentence = sentence + str(word) + " "
#         except:
#             continue
#     data = data + sentence + "\n"

# for sent in tqdm(conll2002.sents()):
#     sentence = ""
#     for word in sent:
#         try:
#             sentence = sentence + str(word) + " "
#         except:
#             continue
#     data = data + sentence + "\n"

data = None
with open("totalData.txt", "r") as fin:
    data = fin.read()


total_len = len(data)

filesizes = [1, 2, 5, 10, 50, 100, 200, 400, 500]
for filesize in tqdm(filesizes):
    filename = "../../data/conll_{}kB.txt".format(filesize)
    with open(filename, "w") as fout:
        if filesize*1000 < total_len:
            fout.write(data[0:filesize*1000])
        else:
            byteswrite = 0
            for i in range((filesize*1000)//total_len):
                byteswrite += total_len
                fout.write(data[0:total_len])
            fout.write(data[0:(filesize*1000)%total_len])
            

