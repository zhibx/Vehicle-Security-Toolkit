import os
import re
import pandas as pd

def analyze_log(log_file):
    results = {
        "activity组件暴露": "未知",
        "activity越权访问": "手动测试",
        "service组件暴露": "未知",
        "broadcast receiver组件暴露": "未知",
        "content provider组件暴露": "未知",
        "content provider Uri": "未知",
        "content provider SQL注入": "未知",
        "组件导出暴露": "未知",
        "URL泄露风险": "未知"
    }

    sensitive_patterns = [
        re.compile(r'password', re.IGNORECASE),
        re.compile(r'key', re.IGNORECASE),
        re.compile(r'secret', re.IGNORECASE),
        re.compile(r'token', re.IGNORECASE),
        re.compile(r'phone', re.IGNORECASE),
        re.compile(r'\b\d{10}\b'),  # 简单手机号匹配
        re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),  # 简单身份证匹配
    ]

    with open(log_file, 'r', encoding='utf-8') as file:
        log_content = file.read()

        # 检查 activity 组件暴露
        if "run app.activity.info" in log_content:
            if "No matching activities" in log_content:
                results["activity组件暴露"] = "通过"
            elif "Permission: null" in log_content:
                results["activity组件暴露"] = "通过"
                results["activity越权访问"] = "通过"
            else:
                results["activity组件暴露"] = "未知"

        # 检查 service 组件暴露
        if "run app.service.info" in log_content:
            if "No matching services" in log_content:
                results["service组件暴露"] = "通过"
            elif "Permission: null" in log_content:
                results["service组件暴露"] = "通过"
            else:
                results["service组件暴露"] = "未知"

        # 检查 broadcast receiver 组件暴露
        if "run app.broadcast.info" in log_content:
            if "No matching receivers" in log_content:
                results["broadcast receiver组件暴露"] = "通过"
            elif "Permission: null" in log_content:
                results["broadcast receiver组件暴露"] = "通过"
            else:
                results["broadcast receiver组件暴露"] = "未知"

        # 检查 content provider 组件暴露
        if "run app.provider.info" in log_content:
            if "No matching providers" in log_content:
                results["content provider组件暴露"] = "通过"
            else:
                providers = re.findall(r'Authority: (.*?)\n.*?Read Permission: (.*?)\n.*?Write Permission: (.*?)\n', log_content, re.DOTALL)
                for provider in providers:
                    authority, read_perm, write_perm = provider
                    if read_perm == "null" and write_perm == "null":
                        results["content provider组件暴露"] = "通过"
                    else:
                        results["content provider组件暴露"] = "存在安全风险"
                        break

        # 检查 content provider Uri
        if "run scanner.provider.finduris" in log_content:
            if "Got a response from content Uri" in log_content:
                uris = re.findall(r'Got a response from content Uri: ([^\s]+)', log_content)
                for uri in uris:
                    if any(pattern.search(uri) for pattern in sensitive_patterns):
                        results["content provider Uri"] = "存在信息泄露风险"
                        break
                if results["content provider Uri"] == "未知":
                    results["content provider Uri"] = "通过"
            else:
                results["content provider Uri"] = "通过"

        # 检查 content provider SQL注入
        if "run scanner.provider.injection" in log_content:
            if "No vulnerabilities found" in log_content:
                results["content provider SQL注入"] = "通过"
            else:
                results["content provider SQL注入"] = "存在安全风险"

        # 检查组件导出暴露
        if "run app.package.attacksurface" in log_content:
            export_pattern = re.compile(r'(\d+) (activities|services|broadcast receivers|content providers) exported')
            matches = export_pattern.findall(log_content)
            if matches:
                # 如果存在导出的组件，检查它们的具体权限
                for match in matches:
                    count, component = match
                    if int(count) > 0:
                        results["组件导出暴露"] = "通过"
            else:
                results["组件导出暴露"] = "通过"

        # 检查 URL泄露风险
        if "run scanner.provider.finduris" in log_content:
            uris = re.findall(r'Got a response from content Uri: ([^\s]+)', log_content)
            for uri in uris:
                if any(pattern.search(uri) for pattern in sensitive_patterns):
                    results["URL泄露风险"] = "存在安全风险"
                    break
            if results["URL泄露风险"] == "未知":
                results["URL泄露风险"] = "通过"

    return results

def main():
    log_dir = "./drozer-tester/logs"
    logs = [os.path.join(log_dir, log) for log in os.listdir(log_dir) if log.endswith(".log")]
    analysis_results = []

    for log_file in logs:
        package_name = os.path.basename(log_file).replace("_drozer.log", "")
        results = analyze_log(log_file)
        results["package"] = package_name
        analysis_results.append(results)

    df = pd.DataFrame(analysis_results)
    df.set_index("package", inplace=True)
    print(df)
    df.to_csv("analysis_results.csv")

if __name__ == "__main__":
    main()
