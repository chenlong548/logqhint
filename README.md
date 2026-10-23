# 基本用法：对日志文件按关键词筛查
python logqhint.py access.log --keyword "error"

# 正则模式匹配
python logqhint.py access.log --regex "FAILED\s+login"

# 输出命中行与统计摘要
python logqhint.py access.log --keyword "error" --stats