from urllib.parse import urlparse
from sentence_transformers import SentenceTransformer
from halo import Halo
import collections
import math
import torch
import time

def replace_number(df,key):
    """
    Extract unique inputs from the dataframe and mask numeric values.

    Args:
        df (pd.DataFrame): Dataframe containing a 'url' column with log URLs.
        key (str) : Key of columns

    Returns:
        list: output numeric sequences replaced by <NUM>.
    """
    return df[key].str.replace(r'\d+', '<NUM>', regex=True)

def replace_lang(df, key):
    """
    Melakukan generalisasi pada urutan karakter non-ASCII dalam kolom yang ditentukan.

    Args:
        df (pd.DataFrame): DataFrame yang berisi kolom teks.
        key (str): Kunci (nama) dari kolom yang akan diproses.

    Returns:
        pd.Series: Sebuah pandas Series dengan urutan karakter non-ASCII 
                   diganti menjadi '<LANG>'.
    """
    # Regex ini mencari satu atau lebih karakter ([...]+) yang BUKAN (^)
    # bagian dari rentang ASCII standar (\x00-\x7F).
    non_ascii_regex = r'[^\x00-\x7F]+'
    
    return df[key].str.replace(non_ascii_regex, '<LANG>', regex=True)

spinner = Halo(text='Mendeteksi perangkat komputasi...', spinner='dots')
spinner.start()
time.sleep(0.5)

if torch.cuda.is_available() :
    device = "cuda"
    spinner.succeed("Vectorization using GPU")
else : 
    device = "cpu"
    spinner.succeed("Vectorization using CPU")    

model_name_2 = 'all-MiniLM-L6-v2'
model_2 = SentenceTransformer(model_name_2, device=device)

def get_sentence_bert_vector(text):
    """
    Mengambil vektor embedding dari sebuah teks menggunakan SentenceTransformer.
    Inputnya adalah string mentah, tidak perlu di-split.
    """
    # .encode() adalah fungsi utama untuk membuat vektor
    vector = model_2.encode(text, convert_to_tensor=False)
    return vector

def calculate_entropy(s):
    """Menghitung Shannon Entropy untuk sebuah string."""
    if not s:
        return 0.0
    # Hitung frekuensi setiap karakter
    counts = collections.Counter(s)
    length = len(s)
    entropy = 0.0
    # Hitung entropi
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def safe_url_parse(url):
    try: return urlparse(str(url)).path
    except: return ""
