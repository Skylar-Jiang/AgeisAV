# 无样本的离线示例

`sha256.txt` 的全 a 哈希只是占位值，不对应任何教师样本或实测结果。
下面命令只记录 CVERC 缺少已核验 API 的阻塞状态（预期退出码 1），不会联网或读取凭据：

```powershell
.venv/Scripts/python.exe -m aegisav.hash_query cverc `
  --input docs/examples/course-query/sha256.txt `
  --output output/course-query/placeholder-cverc
```

不要对这个占位清单使用 `--live`，不要把其输出当作课程平台查询成果。
真实教师 100 项和报告留在本地历史 `apicall` 数据目录；复核命令、手工报告导入格式、来源认证的实际边界见 `docs/COURSE_HASH_QUERY.md`。
