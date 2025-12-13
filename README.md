github 使用个人访问令牌
创建个人访问令牌
登录GitHub，点击右上角头像 -> Settings​ -> 左侧边栏最下方找到 Developer settings。
点击 Personal access tokens​ -> Tokens (classic)​ -> Generate new token​ -> Generate new token (classic)。
为令牌命名（例如 "My Local Machine"），设置过期时间，在权限（scopes）下一定要勾选 repo（包含所有仓库权限），根据需要勾选其他权限

点击页面底部的 Generate token。

使用令牌进行推送
当您再次执行 git push -u origin main时：
Username: 输入您的GitHub用户名 sparkychen。
Password: 这里不再输入您的GitHub登录密码，而是粘贴刚才复制的个人访问令牌。

步骤 1：全局设置凭证助手（关键一步！）
git config --global credential.helper store
步骤 2：执行一次推送（输入一次后永久记住）
git push -u origin main
# 输入 
#   Username: sparkychen
#   Password: ghp_abc123xyz... (你的PAT token)

uv init --python 3.11
uv venv --python 3.11



vllm关键参数解释
--max-num-seqs: 控制同时处理的最大请求数，这是解决此问题的关键参数。从默认的256降到16或8。
--gpu-memory-utilization: 从0.85降到0.7或0.6，为采样器预留更多空间。
--max-model-len: 减少上下文长度可以显著降低KV缓存的内存占用。
--enforce-eager: 禁用图优化，减少编译期间的内存峰值。
--disable-custom-all-reduce: 禁用自定义通信，减少开销
PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
vllm serve /opt/models/hf/Qwen/Qwen3-4B-Thinking-2507-FP8 --tensor-parallel-size 1 --gpu-memory-utilization 0.85 --max-num-seqs 32 --max-model-len 4096 --port 8000

# 编译dolphinscheduler-3.1.9 src源码，在windows上编译：(mvn spotless:apply)
mvn clean package -DskipTests -D"spotless.check.skip"=true -X -e


CREATE USER postgres123 WITH PASSWORD 'pgsAdmin@123';
# windows
GRANT CREATE ON SCHEMA public TO postgres123;
GRANT ALL PRIVILEGES ON DATABASE fastxai TO postgres123;
# linux
GRANT ALL PRIVILEGES ON DATABASE fastxai TO postgres123;
GRANT USAGE, CREATE ON SCHEMA public TO postgres123;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO postgres123;
LTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON SEQUENCES TO postgres123;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL PRIVILEGES ON TYPES TO postgres123;
ALTER DATABASE fastxai OWNER TO postgres123;
 
 #adbc-driver-flightsql 

 # 启动 dev：通过 uv run uvicorn --reload（或配置快捷脚本 uv run dev）启动调试服务
