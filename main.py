import os
import argparse
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.decomposition import PCA
from sklearn.cluster import AgglomerativeClustering
from sklearn.metrics import silhouette_score
from helper.feature_engineering import replace_number,split_url_tokens,get_bert_vector_tf,safe_url_parse,calculate_entropy
from helper.pattern import get_attack_pattern
from helper.decoder import parse_dec_file_to_dataframe
from helper.report import generate_report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parser log file clustering")
    parser.add_argument("--logfile", type=str, required=True, help="Path ke log file")
    args = parser.parse_args()    

    logfile = args.logfile
    df = parse_dec_file_to_dataframe(logfile)

    # FEATURE ENGINEERING
    print("Proses Feature Engineering Sedang Berjalan...")

    df['time'] = pd.to_datetime(df['time'])
    df = df.sort_values('time').reset_index(drop=True)
    df['time'] = df['time'] + pd.to_timedelta(df.groupby('time').cumcount(), unit='ns')


    df['pathname'] = df['url'].apply(safe_url_parse)
    df['dummy_count'] = 1
    df['url_code'] = df['url'].astype('category').cat.codes
    df['pathname_code'] = df['pathname'].astype('category').cat.codes

    suspicious_ua_keywords = ['wget', 'curl', 'nmap', 'sqlmap', 'nikto', 'python-requests', 'postman', 'java/', 'go-http-client']
    ua_regex = '|'.join(suspicious_ua_keywords)
    df['is_script_or_scanner'] = df['user_agent'].str.lower().str.contains(ua_regex, na=False).astype(int)
    
    df['is_error'] = (df['status'] >= 400).astype(int)
    df_indexed = df.set_index('time')

    ip_rolling_base = df_indexed.groupby('ip').rolling('5min')
    base_aggs = ip_rolling_base.agg({
        'dummy_count': 'sum',
        'is_error': 'sum',
        'size': 'mean'
    })

    unique_aggs = ip_rolling_base['pathname_code'].apply(lambda x: x.nunique())
    unique_aggs.name = 'unique_pathname_count_5min'
    ip_rolling_aggs = base_aggs.join(unique_aggs)
    ip_rolling_aggs = ip_rolling_aggs.reset_index()
    
    ip_rolling_aggs = ip_rolling_aggs.rename(columns={
        'dummy_count': 'request_count_5min',
        'is_error': 'error_count_5min',
        'size': 'avg_size_per_ip_5min'
    })

    ip_rolling_aggs['ip_error_rate_5min'] = (ip_rolling_aggs['error_count_5min'] / ip_rolling_aggs['request_count_5min']).fillna(0)

    df = pd.merge(df, ip_rolling_aggs, on=['ip', 'time'], how='left')

    df['time_since_last_req_sec'] = df.groupby('ip')['time'].diff().dt.total_seconds()

    df[['request_count_5min', 'unique_pathname_count_5min']] = df[['request_count_5min', 'unique_pathname_count_5min']].fillna(1)
    df[['ip_error_rate_5min', 'avg_size_per_ip_5min']] = df[['ip_error_rate_5min', 'avg_size_per_ip_5min']].fillna(0)
    df['time_since_last_req_sec'] = df['time_since_last_req_sec'].fillna(3600)

    df['time_sec'] = df['time'].dt.round('S')
    requests_per_second = df.groupby(['pathname_code', 'time_sec'])['dummy_count'].transform('size')
    df['pathname_requests_per_sec'] = requests_per_second

    df['hour'] = df['time'].dt.hour
    df['day_of_week'] = df['time'].dt.dayofweek
    is_weekend = df['day_of_week'] >= 5
    is_after_hours = (df['hour'] < 7) | (df['hour'] > 19)
    df['is_off_hours'] = (is_weekend | is_after_hours).astype(int)
    df['hour_sin'] = np.sin(2 * np.pi * df['hour'] / 24)
    df['hour_cos'] = np.cos(2 * np.pi * df['hour'] / 24)
    df['day_of_week_sin'] = np.sin(2 * np.pi * df['day_of_week'] / 7)
    df['day_of_week_cos'] = np.cos(2 * np.pi * df['day_of_week'] / 7)
    df['url_str'] = df['url'].astype(str)
    df['url_length'] = df['url_str'].str.len()
    df['special_char_count'] = df['url_str'].str.count(r'[\'\"<>\(\);]')
    df['path_depth'] = df['url_str'].str.count('/')
    df['url_entropy'] = df['url_str'].apply(calculate_entropy)

    attack_patterns = get_attack_pattern()
    for attack_type, patterns in attack_patterns.items():
        attack_patterns[attack_type] = [f'(?i){p}' for p in patterns]
    url_lower = df['url_str'].str.lower()
    all_patterns = [pattern for pattern_list in attack_patterns.values() for pattern in pattern_list]
    combined_regex = '|'.join(all_patterns)
    df['attack_pattern_count'] = url_lower.str.count(combined_regex)

    columns_to_drop = [
        'dummy_count', 'url_code', 'pathname_code', 'is_error', 'error_count_5min',
        'hour', 'day_of_week'
    ]
    df = df.drop(columns=columns_to_drop)
    print("Proses Feature Engineering Selesai")

    # VECTORIZAITION URL, REFERRER, USER AGENT USING BERT MODEL
    print("Proses Vektorisasi BERT Sedang Berjalan...")

    df['url_prepped'] = replace_number(df, "url_str")
    df["url_vec"] = df['url_prepped'].apply(split_url_tokens)
    df["url_vec"] = df['url_vec'].apply(lambda x: get_bert_vector_tf(x, is_split=True))    

    print("Proses Vektorisasi BERT Selesai")

    # MERGE NUMERICAL,CATEGORICAL,VECTOR
    numerical_features = [
    'size', 'request_count_5min', 'unique_pathname_count_5min',
    'avg_size_per_ip_5min', 'ip_error_rate_5min','pathname_requests_per_sec', 'time_since_last_req_sec',
    'is_off_hours', 'hour_sin', 'hour_cos','day_of_week_sin','day_of_week_cos',
    'url_length',  'path_depth', 'url_entropy', 'attack_pattern_count','is_script_or_scanner'
    ]

    categorical_features = ['method', 'protocol', 'status']
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

    # HYPERPARAMETER BEST THRESHOLD        
    threshold_range = np.arange(90, 210, 5)
    best_score = -1  
    best_threshold = 0
    best_n_clusters = 0

    results = []

    for threshold in threshold_range:        
        model = AgglomerativeClustering(n_clusters=None, distance_threshold=threshold, linkage='ward')
        labels = model.fit_predict(features_processed)
                
        n_clusters = len(np.unique(labels))
        
        if n_clusters > 1:
            score = silhouette_score(features_processed, labels)
            results.append({'threshold': threshold, 'n_clusters': n_clusters, 'score': score})
            
            print(f"Threshold: {threshold:<5} -> Jumlah Cluster: {n_clusters:<4} -> Silhouette Score: {score:.4f}")
        
            if score > best_score:
                best_score = score
                best_threshold = threshold
                best_n_clusters = n_clusters
        else:
            print(f"Threshold: {threshold:<5} -> Jumlah Cluster: 1 -> Silhouette Score tidak dapat dihitung.")

    # CLUSTERING PROCESS    
    print("Proses Clustering Sedang Berjalan...")

    final_model = AgglomerativeClustering(n_clusters=None, distance_threshold=best_threshold, linkage='ward')
    final_labels = final_model.fit_predict(features_processed)
    df["cluster"] = final_labels    

    print("Proses Clustering Selesai")

    # POST CLUSTERING
    print("Proses Post Clustering Sedang Berjalan...")

    df['label'] = 'Normal'
    df['is_rule_anomaly'] = df['attack_pattern_count'].apply(lambda x: x > 0)
    df.loc[df['is_rule_anomaly'], 'label'] = "Suspected_As_An_Attack"

    df.loc[df['is_script_or_scanner'] == 1,'label'] = 'Suspected_As_An_Attack'

    DDOS_PER_SEC_THRESHOLD = 20
    df.loc[df['pathname_requests_per_sec'] > DDOS_PER_SEC_THRESHOLD, 'label'] = 'Suspected_As_An_Attack'

    cluster_stats = df.groupby('cluster').agg(
        cluster_size=('cluster', 'count'),
        avg_req_rate=('request_count_5min', 'mean'),
        avg_unique_pathnames=('unique_pathname_count_5min', 'mean')
    ).reset_index()

    scanner_clusters = cluster_stats[(cluster_stats['cluster_size'] > 20) & (cluster_stats['avg_unique_pathnames'] > 15)]['cluster']
    df.loc[df['cluster'].isin(scanner_clusters), 'label'] = 'Suspected_As_An_Attack'

    bruteforce_clusters = cluster_stats[(cluster_stats['cluster_size'] > 20) & (cluster_stats['avg_unique_pathnames'] <= 2) & (cluster_stats['avg_req_rate'] > 15)]['cluster']
    df.loc[df['cluster'].isin(bruteforce_clusters), 'label'] = 'Suspected_As_An_Attack'

    cluster_sizes = df['cluster'].value_counts()
    rarity_clusters = cluster_sizes[cluster_sizes <= 1].index
    df.loc[
        (df['label'] == 'Normal') &
        (df['cluster'].isin(rarity_clusters)) &
        (df['status'] >= 400),
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
    'ip', 'time', 'status', 'url','user_agent','cluster',"label"
    ]    

    # SAVE OUTPUT 
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True) 
    
    output_path = os.path.join(output_dir, "report.csv")
    df[output_columns].sort_values(by=['cluster']).to_csv(output_path, index=False)

    # GENERATE REPORT
    generate_report()
	