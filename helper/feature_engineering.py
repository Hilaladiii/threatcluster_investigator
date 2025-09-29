import re
import torch
from urllib.parse import urlparse, unquote
from transformers import BertTokenizer, BertModel
import collections
import math

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

def split_url_tokens(url):
    """Tokenisasi URL dengan memisahkan path dan query string."""
    parsed = urlparse(url)
    path = unquote(parsed.path)
    query = unquote(parsed.query)
    delimiters = r"[\/\-\_\=\&\?\.\+\(\)\[\]\<\>\{\}]"
    tokens = re.split(delimiters, path.strip("/")) + re.split(delimiters, query)
    return " ".join([tok for tok in tokens if tok])


model_name = 'bert-base-multilingual-cased'
tokenizer = BertTokenizer.from_pretrained(model_name)
model = BertModel.from_pretrained(model_name)

def get_bert_vector_tf(text, is_split=False):
    """
    Mengambil vektor embedding [CLS] dari sebuah teks menggunakan model TensorFlow.
    """    
    inputs = tokenizer(
        text, 
        return_tensors="pt", 
        truncation=True, 
        padding=True, 
        max_length=128,
        is_split_into_words=is_split
    )
    
    with torch.no_grad():
        outputs = model(**inputs)
    
    vector = outputs.last_hidden_state[:, 0, :].squeeze()
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
