import argparse
import pandas as pd
import numpy as np
import time
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.decomposition import PCA
from sklearn.metrics import v_measure_score, homogeneity_score, completeness_score
from helper.feature_engineering import replace_number,replace_lang,get_sentence_bert_vector,safe_url_parse
from helper.pattern import get_attack_pattern,get_first_attack_type
from helper.decoder import parse_dec_file_to_dataframe
from helper.report import generate_report
import fastcluster
from scipy.cluster.hierarchy import fcluster
from halo import Halo
import re


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parser log file clustering")
    parser.add_argument("--logfile", type=str, required=True, help="Path ke log file")
    args = parser.parse_args()    
    logfile = args.logfile
        
    TARGET_DATA_SIZE = 40000

    # ==============================================================================
    # FILTERING VALID BOT
    # ==============================================================================    

    spinner = Halo(text='Filtering LOG BOT...', spinner='dots')
    spinner.start()    
    bot_time = time.time()
    
    df = parse_dec_file_to_dataframe(logfile)    

    bot_end_time = time.time() 
    bot_execution_time = bot_end_time - bot_time
    
    spinner.succeed(f"Filtering LOG BOT Selesai. Waktu yang dibutuhkan: {bot_execution_time:.2f} detik.")    

    # ==============================================================================
    # INITIAL FEATURE ENGINEERING 
    # ==============================================================================    
    spinner_first_fe = Halo(text='Memulai Proses Feature Engineering Fase Awal', spinner='dots')
    spinner_first_fe.start()

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

    spinner_first_fe.succeed(f"Feature Engineering Fase Awal Selesai. Waktu yang dibutuhkan: {first_fe_execution_time:.2f} detik")

    # ==============================================================================
    # DATA REDUCTION
    # ==============================================================================

    spinner_reduction = Halo(text='Memulai Proses Reduksi Data', spinner='dots')
    spinner_reduction.start()
    
    reduction_time = time.time()
    
    RPS_THRESHOLD = 100
    df['keep_row'] = (
        (df['attack_pattern_count'] > 0) |
        (df['is_script_or_scanner'] == 1) |
        (df['pathname_requests_per_sec'] > RPS_THRESHOLD)     
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
        
    df_common_patterns_only = df[df['generalized_pathname'].isin(common_generalized_patterns)]
    pattern_success_rate = df_common_patterns_only.groupby('generalized_pathname')['status_numeric'].apply(
        lambda x: (x.between(200, 399)).mean() if not x.empty else 0
    )
    SUCCESS_RATE_THRESHOLD = 0.95 
    truly_normal_common_patterns = pattern_success_rate[pattern_success_rate > SUCCESS_RATE_THRESHOLD].index    
    
    is_common_normal_pattern = df['generalized_pathname'].isin(truly_normal_common_patterns)

    rows_to_drop_mask = (is_duplicate | is_common_normal_pattern) & (~df['keep_row'])
    
    df_reduced = df[~rows_to_drop_mask].reset_index(drop=True)            
    
    if len(df_reduced) > TARGET_DATA_SIZE:        
            
        df_anomalous = df_reduced[df_reduced['keep_row'] == True].copy()
        df_normal = df_reduced[df_reduced['keep_row'] == False].copy()
        
        n_anomalous = len(df_anomalous)
        n_normal_quota = TARGET_DATA_SIZE - n_anomalous
        
        if n_normal_quota <= 0:            
            df_final_sample = df_anomalous.sample(n=TARGET_DATA_SIZE, random_state=42)
        else:            
            if len(df_normal) > n_normal_quota:             
                df_normal_sample = df_normal.sample(n=n_normal_quota, random_state=42)
                df_final_sample = pd.concat([df_anomalous, df_normal_sample], ignore_index=True)
            else:                
                df_final_sample = pd.concat([df_anomalous, df_normal], ignore_index=True)
                
        df = df_final_sample.sample(frac=1, random_state=42).reset_index(drop=True)
    else:        
        df = df_reduced
        
    df = df.drop(columns=['keep_row', 'generalized_pathname', 'dummy_count', 'pathname_code', 'time_sec'], errors='ignore') 
    
        
    df = df.sort_values('time').reset_index(drop=True)        

    reduction_end_time = time.time() 
    reduction_execution_time = reduction_end_time - reduction_time    

    spinner_reduction.succeed(f"\nUkuran data final untuk diproses: {len(df)} baris. Waktu yang dibutuhkan: {reduction_execution_time:.2f} detik")
    
    # ==============================================================================
    # FINAL FEATURE ENGINEERING 
    # ==============================================================================    
    
    spinner_last_fe = Halo(text='Memulai Feature Engineering Fase Akhir Reduksi Data', spinner='dots')
    spinner_last_fe.start()

    last_fe_time = time.time()  
    df['pathname_code'] = df['pathname'].astype('category').cat.codes
    df['is_error'] = (df['status_numeric'] >= 400).astype(int)
    df['dummy_count'] = 1
    df_indexed = df.set_index('time')
    
    ip_rolling_base = df_indexed.groupby('ip').rolling('1min')        
    base_aggs = ip_rolling_base.agg({'dummy_count': 'sum'}) 
    
    unique_aggs = ip_rolling_base['pathname_code'].apply(lambda x: x.nunique())
    unique_aggs.name = 'unique_pathname_count_1min'
    ip_rolling_aggs = base_aggs.join(unique_aggs)
    ip_rolling_aggs = ip_rolling_aggs.reset_index()        
    ip_rolling_aggs = ip_rolling_aggs.rename(columns={'dummy_count': 'request_count_1min'})
        
    
    df = pd.merge(df, ip_rolling_aggs, on=['ip', 'time'], how='left')
        
    
    df[['request_count_1min', 'unique_pathname_count_1min']] = df[['request_count_1min', 'unique_pathname_count_1min']].fillna(1)
        
    columns_to_drop_fe = ['dummy_count', 'pathname_code', 'is_error', 'time_sec']
    df = df.drop(columns=columns_to_drop_fe, errors='ignore')


    last_fe_end_time = time.time() 
    last_fe_execution_time = last_fe_end_time - last_fe_time
        
    spinner_last_fe.succeed(f"Feature Engineering Akhir Selesai. Waktu yang dibutuhkan: {last_fe_execution_time:.2f} detik")

    # VECTORIZAITION URL
    spinner_vector = Halo(text='Memulai Vektorisasi URL', spinner='dots')
    spinner_vector.start()

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
            df['pathname_requests_per_sec'] > RPS_THRESHOLD,
            "rpsh", 
            ""     
        )
    )
    df['url_prepped_for_bert'] = df['bert_prefix'] + ' ' + df['url_prepped']        

    list_of_urls = df['url_prepped_for_bert'].tolist()
    url_vectors = get_sentence_bert_vector(list_of_urls) 
    df['url_vec'] = list(url_vectors)

    end_time = time.time() 
    execution_time = end_time - start_time    

    spinner_vector.succeed(f"Proses Vektorisasi URL Selesai. Waktu yang dibutuhkan: {execution_time:.2f} detik")
        
    numerical_features = ['pathname_requests_per_sec', 'attack_pattern_count']    
    vector_cols = ['url_vec']    

    vector_dfs = []
    for col in vector_cols:
        df_v = pd.DataFrame(df[col].tolist(), index=df.index).add_prefix(f'{col}_')
        vector_dfs.append(df_v)

    df_features = pd.concat([df[numerical_features]] + vector_dfs, axis=1)        

    # ==============================================================================
    # STANDARITATION & PCA
    # ==============================================================================        

    spinner_pca = Halo(text="Memulai Standarisasi dan PCA", spinner="dots")
    spinner_pca.start()

    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('pca', PCA(n_components=0.95))
    ])
    features_processed = pipeline.fit_transform(df_features)                
    spinner_pca.succeed("Proses Standarisasi dan PCA Selesai")
    
    # ==============================================================================
    # CLUSTERING 
    # ==============================================================================    
    spinner_clustering = Halo(text="Memulai Komputasi Agglomerative Clustering", spinner="dots")
    spinner_clustering.start()

    start_time = time.time()

    labels_true = np.where(
        (df['attack_pattern_count'] > 0) |
        (df['is_script_or_scanner'] == 1) |
        (df['pathname_requests_per_sec'] > RPS_THRESHOLD),
        1, 
        0 
    )
        
    start_time = time.time()
    linkage_matrix = fastcluster.linkage(features_processed, method='ward')
    end_time = time.time()    

    n_samples = len(features_processed)    

    best_n_clusters = np.maximum(10,int(np.sqrt(n_samples) * 0.15))    

    
    final_labels = fcluster(linkage_matrix, t=best_n_clusters, criterion='maxclust')

    df["cluster"] = final_labels - 1
    labels_pred = df["cluster"]

    end_time = time.time() 
    execution_time = end_time - start_time
    
    spinner_clustering.succeed(f"Proses Komputasi Selesai. Waktu yang dibutuhkan: {execution_time:.2f} detik")
    
    # ==============================================================================
    # EXTERNAL METRIC EVALUATION
    # ==============================================================================

    print("\n--- Mengevaluasi Performa Deteksi Serangan (Validasi Eksternal) ---")
    
    if len(labels_true) != len(labels_pred):
        print("Error: Panjang Ground Truth dan Label Prediksi tidak cocok!")
    else:        
        v_measure = v_measure_score(labels_true, labels_pred)
        homogeneity = homogeneity_score(labels_true, labels_pred)
        completeness = completeness_score(labels_true, labels_pred)
        
        print(f"V-measure Score          : {v_measure:.4f}")
        print(f"  - Homogeneity: {homogeneity:.4f} ")
        print(f"  - Completeness : {completeness:.4f} ")

    # ==============================================================================
    # POST CLUSTERING
    # ==============================================================================

    spinner_post_clustering = Halo("Memulai Post Clustering",spinner="dots")
    spinner_post_clustering.start()

    df['label'] = 'Normal'
    df['is_rule_anomaly'] = df['attack_pattern_count'].apply(lambda x: x > 0)
    df.loc[df['is_rule_anomaly'], 'label'] = "Suspected_As_An_Attack"

    df.loc[df['is_script_or_scanner'] == 1,'label'] = 'Suspected_As_An_Attack'

    DDOS_PER_SEC_THRESHOLD = 100
    df.loc[df['pathname_requests_per_sec'] > DDOS_PER_SEC_THRESHOLD, 'label'] = 'Suspected_As_An_Attack'

    cluster_stats = df.groupby('cluster').agg(
        cluster_size=('cluster', 'count'),
        avg_req_rate=('request_count_1min', 'mean'),
        avg_unique_pathnames=('unique_pathname_count_1min', 'mean')
    ).reset_index()

    scanner_clusters = cluster_stats[(cluster_stats['cluster_size'] > 1000) & (cluster_stats['avg_unique_pathnames'] > 50)]['cluster']
    df.loc[df['cluster'].isin(scanner_clusters), 'label'] = 'Suspected_As_An_Attack'

    bruteforce_clusters = cluster_stats[(cluster_stats['cluster_size'] > 1000) & (cluster_stats['avg_unique_pathnames'] <= 2) & (cluster_stats['avg_req_rate'] > 50)]['cluster']
    df.loc[df['cluster'].isin(bruteforce_clusters), 'label'] = 'Suspected_As_An_Attack'    

    suspicious_ips = set(df[
        (df['label'] == 'Suspected_As_An_Attack') & 
        (df["pathname_requests_per_sec"] > DDOS_PER_SEC_THRESHOLD)
    ]['ip'].unique())
    df.loc[df['ip'].isin(suspicious_ips), 'label'] = 'Suspected_As_An_Attack'
    columns = ["url","attack_pattern_count","pathname_requests_per_sec","request_count_1min","unique_pathname_count_1min"]
    df[columns].to_csv("after_post_clustering.csv")
    
    spinner_post_clustering.succeed("Proses Post Clustering Selesai")

    # ==============================================================================
    # REPORTING
    # ==============================================================================
    
    generate_report(df)
