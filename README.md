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

