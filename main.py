import os
import argparse
import pandas as pd
import numpy as np
import time
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score, v_measure_score, homogeneity_score, completeness_score
from helper.feature_engineering import replace_number,replace_lang,get_sentence_bert_vector,safe_url_parse
from helper.pattern import get_attack_pattern,get_first_attack_type
from helper.decoder import parse_dec_file_to_dataframe
from helper.report import generate_report
import fastcluster
from scipy.cluster.hierarchy import fcluster
import re

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parser log file clustering")
    parser.add_argument("--logfile", type=str, required=True, help="Path ke log file")
    args = parser.parse_args()    

    logfile = args.logfile
    
    # TENTUKAN TARGET UKURAN DATA ANDA DI SINI
    TARGET_DATA_SIZE = 40000

    print("Filtering LOG BOT...")
    bot_time = time.time()
    
    df = parse_dec_file_to_dataframe(logfile)
    print(f"Data asli dimuat: {len(df)} baris.")

    bot_end_time = time.time() 
    bot_execution_time = bot_end_time - bot_time
    
    print(f"Filtering LOG BOT Selesai. Waktu yang dibutuhkan: {bot_execution_time:.2f} detik")
    

    # ==============================================================================
    # FEATURE ENGINEERING AWAL (Untuk Aturan & Reduksi)
    # ==============================================================================
    print("Proses Feature Engineering Awal Sedang Berjalan...")
    first_fe_time = time.time()

    df['time'] = pd.to_datetime(df['time'], errors='coerce') 
    df.dropna(subset=['time'], inplace=True) 
    df = df.sort_values('time').reset_index(drop=True)
    df['time'] = df['time'] + pd.to_timedelta(df.groupby('time').cumcount(), unit='ns')
    df['pathname'] = df['url'].apply(safe_url_parse)
    df['dummy_count'] = 1 
    df['url_str'] = df['url'].astype(str) 
    
    attack_patterns = get_attack_pattern()
    all_patterns = [f'(?i){p}' for pattern_list in attack_patterns.values() for p in pattern_list]
    combined_regex = '|'.join(all_patterns)
    df['attack_pattern_count'] = df['url_str'].str.lower().str.count(combined_regex)

    suspicious_ua_keywords = ['nmap', 'sqlmap', 'nikto']
    ua_regex = '|'.join(suspicious_ua_keywords)
    df['is_script_or_scanner'] = df['user_agent'].str.lower().str.contains(ua_regex, na=False).astype(int)

    df['status_numeric'] = pd.to_numeric(df['status'], errors='coerce').fillna(0)

    df['pathname_code'] = df['pathname'].astype('category').cat.codes 
    df['time_sec'] = df['time'].dt.round('s')
    try:
        requests_per_second = df.groupby(['pathname_code', 'time_sec'])['dummy_count'].transform('size')
        df['pathname_requests_per_sec'] = requests_per_second
    except Exception as e:
        df['pathname_requests_per_sec'] = 1
    
    df['pathname_requests_per_sec'] = np.where(
        df['attack_pattern_count'] > 0, 
        1,  
        requests_per_second 
    )

    first_fe_end_time = time.time() 
    first_fe_execution_time = first_fe_end_time - first_fe_time

    print(f"Feature Engineering Awal Selesai. Waktu yang dibutuhkan: {first_fe_execution_time:.2f} detik")    

    # ==============================================================================
    # REDUKSI DATA CERDAS (DENGAN KUOTA)
    # ==============================================================================
    print("\nMemulai Proses Reduksi Data Cerdas...")
    reduction_time = time.time()
    
    DDOS_PER_SEC_THRESHOLD = 100
    df['keep_row'] = (
        (df['attack_pattern_count'] > 0) |
        (df['is_script_or_scanner'] == 1) |
        (df['pathname_requests_per_sec'] > DDOS_PER_SEC_THRESHOLD)     
    )

    df["generalized_pathname"] = df["pathname"].astype(str)
    df['generalized_pathname'] = replace_number(df, "generalized_pathname")
    df['generalized_pathname'] = replace_lang(df, "generalized_pathname")

    similarity_key = ["generalized_pathname"] 
    for col in similarity_key:
        if col not in df.columns: is_duplicate = pd.Series([False]*len(df), index=df.index); break
    else: is_duplicate = df.duplicated(subset=similarity_key, keep='first')    
    
    generalized_counts = df['generalized_pathname'].value_counts()
        
    COMMON_PATTERN_THRESHOLD = 400
    common_generalized_patterns = generalized_counts[generalized_counts > COMMON_PATTERN_THRESHOLD].index
    print(f"Mengidentifikasi {len(common_generalized_patterns)} pola pathname umum untuk dipertimbangkan dihapus (jika normal).")
        
    df_common_patterns_only = df[df['generalized_pathname'].isin(common_generalized_patterns)]
    pattern_success_rate = df_common_patterns_only.groupby('generalized_pathname')['status_numeric'].apply(
        lambda x: (x.between(200, 399)).mean() if not x.empty else 0
    )
    SUCCESS_RATE_THRESHOLD = 0.80 
    truly_normal_common_patterns = pattern_success_rate[pattern_success_rate > SUCCESS_RATE_THRESHOLD].index
    print(f"Dari pola umum, {len(truly_normal_common_patterns)} dikonfirmasi sebagai normal (tingkat sukses > {SUCCESS_RATE_THRESHOLD*100}%).")
    
    is_common_normal_pattern = df['generalized_pathname'].isin(truly_normal_common_patterns)

    rows_to_drop_mask = (is_duplicate | is_common_normal_pattern) & (~df['keep_row'])
    
    df_reduced = df[~rows_to_drop_mask].reset_index(drop=True)
        
    print(f"Ukuran data setelah reduksi cerdas: {len(df_reduced)} baris (dari {len(df)}).")
    
    if len(df_reduced) > TARGET_DATA_SIZE:
        print(f"Ukuran data ({len(df_reduced)}) masih melebihi target ({TARGET_DATA_SIZE}). Melakukan sampling...")
            
        df_anomalous = df_reduced[df_reduced['keep_row'] == True].copy()
        df_normal = df_reduced[df_reduced['keep_row'] == False].copy()
        
        n_anomalous = len(df_anomalous)
        n_normal_quota = TARGET_DATA_SIZE - n_anomalous
        
        if n_normal_quota <= 0:
            print("Peringatan: Jumlah data anomali yang dilindungi melebihi target. Mengambil sampel acak dari data anomali.")
            df_final_sample = df_anomalous.sample(n=TARGET_DATA_SIZE, random_state=42)
        else:
            print(f"Mengambil semua {n_anomalous} data anomali.")
            if len(df_normal) > n_normal_quota:
                print(f"Mengambil sampel acak {n_normal_quota} baris dari {len(df_normal)} data normal.")
                df_normal_sample = df_normal.sample(n=n_normal_quota, random_state=42)
                df_final_sample = pd.concat([df_anomalous, df_normal_sample], ignore_index=True)
            else:
                print(f"Mengambil semua {len(df_normal)} data normal yang tersisa.")
                df_final_sample = pd.concat([df_anomalous, df_normal], ignore_index=True)
                
        df = df_final_sample.sample(frac=1, random_state=42).reset_index(drop=True)
    else:
        print("Ukuran data sudah di dalam target. Tidak perlu sampling tambahan.")
        df = df_reduced
        
    df = df.drop(columns=['keep_row', 'generalized_pathname', 'dummy_count', 'pathname_code', 'time_sec'], errors='ignore') 
    
        
    df = df.sort_values('time').reset_index(drop=True)        

    reduction_end_time = time.time() 
    reduction_execution_time = reduction_end_time - reduction_time
    print(f"\nUkuran data final untuk diproses: {len(df)} baris. Waktu yang dibutuhkan: {reduction_execution_time:.2f} detik")    
    
    # ==============================================================================
    # FEATURE ENGINEERING LENGKAP (Pada Data yang Sudah Direduksi)
    # ==============================================================================
    print("Proses Feature Engineering Lengkap Sedang Berjalan...")  
    last_fe_time = time.time()  
    df['pathname_code'] = df['pathname'].astype('category').cat.codes
    df['is_error'] = (df['status_numeric'] >= 400).astype(int)
    df['dummy_count'] = 1
    df_indexed = df.set_index('time')
    
    ip_rolling_base = df_indexed.groupby('ip').rolling('5min')        
    base_aggs = ip_rolling_base.agg({'dummy_count': 'sum'}) 
    
    unique_aggs = ip_rolling_base['pathname_code'].apply(lambda x: x.nunique())
    unique_aggs.name = 'unique_pathname_count_5min'
    ip_rolling_aggs = base_aggs.join(unique_aggs)
    ip_rolling_aggs = ip_rolling_aggs.reset_index()        
    ip_rolling_aggs = ip_rolling_aggs.rename(columns={'dummy_count': 'request_count_5min'})
        
    
    df = pd.merge(df, ip_rolling_aggs, on=['ip', 'time'], how='left')
        
    
    df[['request_count_5min', 'unique_pathname_count_5min']] = df[['request_count_5min', 'unique_pathname_count_5min']].fillna(1)
        
    columns_to_drop_fe = ['dummy_count', 'pathname_code', 'is_error', 'time_sec']
    df = df.drop(columns=columns_to_drop_fe, errors='ignore')


    last_fe_end_time = time.time() 
    last_fe_execution_time = last_fe_end_time - last_fe_time
    
    print(f"Feature Engineering Akhir Selesai. Waktu yang dibutuhkan: {last_fe_execution_time:.2f} detik")
    

    # VECTORIZAITION URL, REFERRER, USER AGENT USING BERT MODEL
    print("Proses Vektorisasi BERT Sedang Berjalan...")
    start_time = time.time()

    df['url_prepped'] = replace_number(df, "url_str")
    df['url_prepped'] = replace_lang(df, "url_prepped")

    
    attack_patterns = get_attack_pattern()
    compiled_patterns = {}
    for attack_type, patterns in attack_patterns.items():            
        joined_patterns = '|'.join(patterns)                
        compiled_patterns[attack_type] = re.compile(joined_patterns, flags=re.IGNORECASE)

    df['attack_type'] = df['url_str'].apply(
        lambda x: get_first_attack_type(x, compiled_patterns)
    )

    df['bert_prefix'] = np.where(    
        df['attack_type'] != "", 
        df['attack_type'],           
        np.where(
            df['pathname_requests_per_sec'] > DDOS_PER_SEC_THRESHOLD,
            "ddos", 
            ""     
        )
    )
    df['url_prepped_for_bert'] = df['bert_prefix'] + ' ' + df['url_prepped']        

    list_of_urls = df['url_prepped_for_bert'].tolist()
    url_vectors = get_sentence_bert_vector(list_of_urls) 
    df['url_vec'] = list(url_vectors)

    end_time = time.time() 
    execution_time = end_time - start_time

    print("Proses Vektorisasi BERT Selesai")
    print(f"Waktu yang dibutuhkan: {execution_time:.2f} detik")
        
    numerical_features = ['pathname_requests_per_sec', 'attack_pattern_count']
    categorical_features = ['status','method']
    vector_cols = ['url_vec']    

    vector_dfs = []
    for col in vector_cols:
        df_v = pd.DataFrame(df[col].tolist(), index=df.index).add_prefix(f'{col}_')
        vector_dfs.append(df_v)

    df_features = pd.concat([df[numerical_features + categorical_features]] + vector_dfs, axis=1)
    df_features = pd.get_dummies(df_features, columns=categorical_features, drop_first=True)

    # STANDARITATION & PCA
    print("Proses Standarisasi dan PCA Sedang Berjalan...")

    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('pca', PCA(n_components=0.95))
    ])
    features_processed = pipeline.fit_transform(df_features)

    print("Proses Standarisasi dan PCA Selesai")

    print("\nMemulai Hyperparameter Tuning untuk fastcluster...")

    labels_true = np.where(
        (df['attack_pattern_count'] > 0) |
        (df['is_script_or_scanner'] == 1) |
        (df['pathname_requests_per_sec'] > DDOS_PER_SEC_THRESHOLD),
        1, 
        0 
    )
    
    print("Menghitung linkage matrix (ini mungkin butuh beberapa saat)...")
    start_time = time.time()
    linkage_matrix = fastcluster.linkage(features_processed, method='ward')
    end_time = time.time()
    print(f"Linkage matrix selesai dalam {end_time - start_time:.2f} detik.")

    n_samples = len(features_processed)
    estimated_best_cluster = int(np.sqrt(n_samples))
    if estimated_best_cluster < 2: estimated_best_cluster = 2    
    cluster_range = range(2,10,2)

    results = []
    print("Menguji jumlah cluster yang berbeda...")
    for n_clusters in cluster_range:
        labels = fcluster(linkage_matrix, t=n_clusters, criterion='maxclust')
        
        # Hitung silhouette score
        score = silhouette_score(features_processed, labels, sample_size=10000, random_state=42)
        results.append({'n_clusters': n_clusters, 'score': score})
        print(f"Jumlah Cluster: {n_clusters:<4} -> Silhouette Score: {score:.4f}")

    if not results:
        print("Tidak dapat menemukan konfigurasi cluster yang valid. Menggunakan n_clusters=10 sebagai default.")
        best_n_clusters = 10
    else:
        results_df = pd.DataFrame(results).sort_values(by='score', ascending=False)
        print("\n--- Hasil Hyperparameter Tuning ---")
        print(results_df)

        best_k_auto = results_df.iloc[0]['n_clusters']
        print(f"\nRekomendasi Otomatis: n_clusters = {best_k_auto} (Skor tertinggi)")
        
        while True:
            try:
                user_choice = input(f"\nMasukkan jumlah cluster yang Anda inginkan (misal: {best_k_auto}) atau tekan Enter untuk menggunakan rekomendasi: ")
                if user_choice == "":
                    best_n_clusters = int(best_k_auto)
                    print(f"Menggunakan nilai rekomendasi: {best_n_clusters}")
                    break
                
                user_k = int(user_choice)
                if user_k > 1:
                    best_n_clusters = user_k
                    print(f"Anda memilih untuk menggunakan n_clusters = {best_n_clusters}")
                    break
                else:
                    print("Jumlah cluster harus lebih besar dari 1.")
            except ValueError:
                print("Input tidak valid. Harap masukkan angka bulat.")

    # ==============================================================================
    # CLUSTERING PROCESS FINAL (Menggunakan fastcluster)
    # ==============================================================================
    print("\nProses Clustering Final Sedang Berjalan...")
    start_time = time.time()
    
    final_labels = fcluster(linkage_matrix, t=best_n_clusters, criterion='maxclust')

    df["cluster"] = final_labels - 1
    labels_pred = df["cluster"]

    end_time = time.time() 
    execution_time = end_time - start_time

    print("Proses Clustering Selesai")
    print(f"Waktu yang dibutuhkan: {execution_time:.2f} detik")
    
    # ==============================================================================
    # 4. EVALUASI PERFORMA DETEKSI (METRIK BARU ANDA)
    # ==============================================================================

    print("\n--- Mengevaluasi Performa Deteksi Serangan (Validasi Eksternal) ---")
    
    if len(labels_true) != len(labels_pred):
        print("Error: Panjang Ground Truth dan Label Prediksi tidak cocok!")
    else:        
        v_measure = v_measure_score(labels_true, labels_pred)
        homogeneity = homogeneity_score(labels_true, labels_pred)
        completeness = completeness_score(labels_true, labels_pred)
        
        print(f"V-measure Score          : {v_measure:.4f}")
        print(f"  - Homogeneity (Kemurnian): {homogeneity:.4f} (Apakah klaster hanya berisi satu jenis label?)")
        print(f"  - Completeness (Kelengkapan): {completeness:.4f} (Apakah semua label 'Serangan' masuk ke klaster yang sama?)")

    # ==============================================================================
    # POST CLUSTERING
    # ==============================================================================

    print("Proses Post Clustering Sedang Berjalan...")

    df['label'] = 'Normal'
    df['is_rule_anomaly'] = df['attack_pattern_count'].apply(lambda x: x > 0)
    df.loc[df['is_rule_anomaly'], 'label'] = "Suspected_As_An_Attack"

    df.loc[df['is_script_or_scanner'] == 1,'label'] = 'Suspected_As_An_Attack'

    DDOS_PER_SEC_THRESHOLD = 100
    df.loc[df['pathname_requests_per_sec'] > DDOS_PER_SEC_THRESHOLD, 'label'] = 'Suspected_As_An_Attack'

    cluster_stats = df.groupby('cluster').agg(
        cluster_size=('cluster', 'count'),
        avg_req_rate=('request_count_5min', 'mean'),
        avg_unique_pathnames=('unique_pathname_count_5min', 'mean')
    ).reset_index()

    scanner_clusters = cluster_stats[(cluster_stats['cluster_size'] > 1000) & (cluster_stats['avg_unique_pathnames'] > 50)]['cluster']
    df.loc[df['cluster'].isin(scanner_clusters), 'label'] = 'Suspected_As_An_Attack'

    bruteforce_clusters = cluster_stats[(cluster_stats['cluster_size'] > 1000) & (cluster_stats['avg_unique_pathnames'] <= 2) & (cluster_stats['avg_req_rate'] > 50)]['cluster']
    df.loc[df['cluster'].isin(bruteforce_clusters), 'label'] = 'Suspected_As_An_Attack'

    cluster_sizes = df['cluster'].value_counts()
    rarity_clusters = cluster_sizes[cluster_sizes <= 1].index
    df.loc[
        (df['label'] == 'Normal') &
        (df['cluster'].isin(rarity_clusters)) &
        (df['status'] >= 400) &
    (df['attack_pattern_count'] > 0),
        'label'
    ] = 'Suspected_As_An_Attack'

    suspicious_ips = set(df[
        (df['label'] == 'Suspected_As_An_Attack') & 
        (df["pathname_requests_per_sec"] > DDOS_PER_SEC_THRESHOLD)
    ]['ip'].unique())
    df.loc[df['ip'].isin(suspicious_ips), 'label'] = 'Suspected_As_An_Attack'

    print("Proses Post Clustering Selesai")    

    # FORMATTING OUTPUT ANOMALY CLUSTER
    output_columns = [
    'ip', 'time', 'status', 'url','url_prepped','user_agent','cluster',"label"
    ]  

    # SAVE OUTPUT 
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True) 
    
    output_path = os.path.join(output_dir, "report.csv")
    df[output_columns].sort_values(by=['cluster']).to_csv(output_path, index=False)    

    # GENERATE REPORT
    generate_report()
