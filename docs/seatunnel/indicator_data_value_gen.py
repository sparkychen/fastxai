# -*- coding: utf-8 -*-

import pymysql
import pandas as pd
from sqlalchemy import create_engine
from urllib.parse import quote_plus

dictionary_tb = "indicator_data.indicator_dictionary_copy3"
instance_tb = "indicator_data.indicator_instance_copy1"
target_table = "nbs_agri_production_stock"
config_version = "v1"
batch_value = "2023Q3"
deault_region = {'region_code': '310000','region_name': '上海市'}
deleted_flag: int = 0

indicator_config = {
    "host": '10.107.99.50',
    "port": 13306, 
    "user": 'data_config',
    "password": 'xxzx@20251111',
    "database": 'economic_security_platform_staging_db',
    "charset": 'utf8mb4'
}
staging_config = {
    "host": "10.107.99.50",
    "port": 13306, 
    "user": "stagingdb",
    "password": "jjxxzx@20250821",
    "database": "economic_security_platform_staging_db",
    "charset": "utf8mb4"
}
stagging_url = f"mysql+pymysql://{staging_config['user']}:{quote_plus(staging_config['password'])}@{staging_config['host']}:{staging_config['port']}/{staging_config['database']}"
print(stagging_url)
indicator_url = f"mysql+pymysql://{indicator_config['user']}:{quote_plus(indicator_config['password'])}@{indicator_config['host']}:{indicator_config['port']}/{indicator_config['database']}"
print(indicator_url)

indicator_conn = pymysql.connect(**indicator_config)
indicator_cursor = indicator_conn.cursor()
staging_engine = create_engine(stagging_url)
indicator_engine = create_engine(indicator_url)

staging_conn = pymysql.connect(**staging_config)
staging_cursor = staging_conn.cursor()

def test_service():
    staging_cursor.execute(f"desc {target_table}")
    tb_meta = staging_cursor.fetchall()
    tb_cols_meta = [col[0] for col in tb_meta]
    print(tb_cols_meta) 
    
    sql_config_count = f"select count(*) from economic_security_platform_staging_db.version_config where table_name='{target_table}' and version_code='{config_version}'"   
    print(sql_config_count)
    count_df = pd.read_sql_query(sql_config_count, indicator_engine)
    print(count_df)
    config_count = count_df.values[0][0]
    print(config_count)
    sql_indicator = f"""
        with indicator_data as (
            select 
                t1.indicator_id,t1.source_data_indicator_name,t1.indicator_name,
                t1.show_indicator_name,t1.frequency,
                t1.source_table,t1.source_code,t1.source_field,
                t2.order_position,t2.identity_value
            from {dictionary_tb} t1,economic_security_platform_staging_db.version_config t2
            where t1.source_table=t2.table_name and t1.source_code=t2.version_key
            and t1.source_table='{target_table}' and t2.version_code='{config_version}'
        )
        select
			t1.indicator_id,t1.source_data_indicator_name,t1.indicator_name,
			t1.show_indicator_name,t1.frequency,
			t1.source_table,t1.source_code,t1.source_field,
            t1.order_position,t1.identity_value,
			t2.series_id,t2.region_code
        from indicator_data t1 left join {instance_tb} t2
        on t1.indicator_id=t2.indicator_id and t1.indicator_name=t2.indicator_name
        where t2.region_code='{deault_region['region_code']}' and t2.deleted=0
    """
    print(sql_indicator)
    indicator_df = pd.read_sql_query(sql_indicator, indicator_engine)    
    print(indicator_df)
    unmatched_indicator_df = indicator_df[indicator_df['series_id'].isna()]    
    print(unmatched_indicator_df)
    matched_indicator_df = indicator_df[indicator_df['series_id'].notna()]
    print(unmatched_indicator_df.shape[0])
    print(matched_indicator_df)
    print(matched_indicator_df.shape[0])
    print(len(indicator_df))
    print(len(unmatched_indicator_df))
    print(len(matched_indicator_df))
    source_fields = indicator_df['source_field'].drop_duplicates().to_list()
    print(source_fields)
    
    sql_table_config = f"select batch_column,identity_column,order_column from table_config where table_name='{target_table}' limit 1"
    table_config_df = pd.read_sql_query(sql_table_config, indicator_engine)    
    print(table_config_df)
    print(table_config_df.columns.array)
    batch_column,identity_column,order_column = table_config_df.values[0]
    if batch_column =="quarter":
        batch_column_time = "LAST_DAY(CONCAT(SUBSTRING(`quarter`, 1, 4), '-', (SUBSTRING(`quarter`, -1, 1) * 3), '-01')) AS time"
    elif "month" == batch_column:
        batch_column_time = "LAST_DAY(CONCAT(SUBSTRING(`month`, 1, 4), '-', SUBSTRING(`month`, -2, 2), '-01')) AS time"
    else:
        batch_column_time = f"{batch_column} AS time"
    deleted_expr = ""   
    if "deleted" in tb_cols_meta: 
        deleted_expr = f" and deleted={deleted_flag}"
    sql_source22 = f"""
            SELECT
                ROW_NUMBER() OVER (ORDER BY {order_column} asc) AS virtual_id,                
                {identity_column},
                {",".join(source_fields)},
                {batch_column_time}
            FROM {target_table} 
            WHERE {batch_column}='{batch_value}' {deleted_expr}
        """
    print(sql_source22)
    source_df2 = pd.read_sql_query(sql_source22, staging_engine)
    print(source_df2)
    source_dfs = []
    for a_field in source_fields:
        df = source_df2[["virtual_id", identity_column, a_field, "time"]].rename(columns={a_field:"value"})
        df['value_type'] = a_field
        print(df)
        source_dfs.append(df)
    source_df = pd.concat(source_dfs, ignore_index=True).sort_values(by='virtual_id')
    print(source_df.columns.array)
    print(indicator_df.columns.array)
    mapping_df = matched_indicator_df[["indicator_id","identity_value","source_field","order_position","series_id"]]
    indicator_dict_df = mapping_df[["indicator_id","identity_value"]].drop_duplicates()
    indicator_dict_df["region_code"] = deault_region["region_code"]
    print(indicator_dict_df)
    print("\n左连接结果（列名不同）:")
    result_df = pd.merge(source_df,
                        mapping_df,
                        left_on=['indicator_name', 'value_type', 'virtual_id'],
                        right_on=['identity_value', 'source_field', "order_position"],                       
                        how='outer', # full outer join
                        indicator=True)
    result_df.drop(columns=["indicator_name","value_type","virtual_id","indicator_id"], inplace=True)    
    print(result_df)
    matched_df = result_df[result_df['_merge'] == 'both']
    matched_count = len(matched_df)
    shall_count = config_count * len(source_fields)
    unmatched_df = result_df[result_df['_merge'] == 'left_only']
    error_df = result_df[result_df['_merge'] == 'right_only']
    if len(error_df) > 0 or shall_count != matched_count:
        err_msg = f"Error: {target_table}表中{batch_value}批次数据异常：和economic_security_platform_staging_db.version_config配置批次不完全匹配！"
        print(err_msg)
        raise ValueError(err_msg)
    # （可选）删除辅助用的 '_merge' 列
    matched_df = matched_df.drop('_merge', axis=1)
    unmatched_df = unmatched_df.drop('_merge', axis=1)
    print("匹配到的：")
    print(matched_df)
    print("未匹配到的：")
    print(unmatched_df)
 
test_service()
