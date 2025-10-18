# BrowserBox Host Header 污染检测报告

Repository：BrowserBox/BrowserBox（https://github.com/BrowserBox/BrowserBox）

Tech Stack 快扫：多服务 Node.js/Express（主 `src/server.js`、`src/ws-server.js`，以及 docs 转换 `src/services/pool/chai`、部署与 Socket 控制等），未发现 Host 白名单或可信代理设定。

## Findings

### Finding #1：Docs 转换服务返回链接受 Host 污染（存在）
- File/Line：`src/services/pool/chai/src/index.js`:L162-L165, L269-L280, L393-L408
- Code Snippet：
  ```js
  app.use((req, res, next) => {
    State.Protocol = req.protocol;
    State.Host = hostAddress ? hostAddress : req.get('host');
    next();
  });
  …
  if ( mime && ARCHIVES.has(mime) && ! DOCUMENTS_THAT_ARE_ARCHIVES.has(ext) ) {
    viewUrl = `${State.Protocol}://${State.Host}/archives/${pdf.filename}/`;
  } else {
    viewUrl = `${State.Protocol}://${State.Host}/uploads/${pdf.filename}.html`;
  }
  …
  if ( redirectToUrl ) {
    res.redirect(sanitizeUrl(viewUrl));
  } else if ( sendURL ) {
    res.type('text/plain');
    res.end(sanitizeUrl(viewUrl));
  }
  State.Files.set(hash, viewUrl);
  ```
- Source → Sink 路径：`req.get('host')` → `State.Host` → 拼接 `viewUrl` → `res.redirect` / `res.end` 返回，并缓存于 `State.Files` 用于后续请求。
- Why Vulnerable：`req.get('host')` 直接读取请求头，无 Host 校验/可信代理限制；第一次命中会把恶意 Host 写入缓存，影响后续合法请求。
- PoC 思路：
  ```bash
  curl -isk -H 'Host: attacker.test' \
    -F 'secret=<DOCS_KEY>' \
    -F 'pdf=@sample.pdf' \
    https://victim-docs.example.com/very-secure-manifest-convert.html
  ```
  响应中的绝对 URL 将替换为 `https://attacker.test/...`；如部署在反代后再配合 `X-Forwarded-Host`。
- 影响评估：影响所有生成/缓存的文档预览链接，易被用于钓鱼、混淆下载来源或污染其他用户的返回值。
- 修复：配置固定的外链基址（如 `DOCS_PUBLIC_BASE=https://docs.example.com`）并基于该常量构造绝对 URL，或改为返回相对路径；同时限制可信代理来源并加入 Host 白名单。

### Finding #2：Deploy 管理服务登录链接可被 Host 污染（存在）
- File/Line：`src/services/pool/deploy/src/server.js`:L341-L345, L374-L388, L783-L828
- Code Snippet：
  ```js
  function makeLoginLink({app_port,token}) {
    return `${GO_SECURE ? 'https' : 'http'}://${State.serverHostname}:${app_port}/login?token=${encodeURIComponent(token)}`;
  }
  …
  app.use((req, res, next) => {
    const newOrigin = `${req.protocol}://${req.get('host')}`;
    if ( req.hostname !== State.serverHostname ) {
      State.serverHostname = req.hostname;
    }
    next();
  });
  …
  res.status(200).send(`…<a target=bb${port} href=${loginLink}>${loginLink}</a>…`);
  …
  res.redirect(connection.loginLink);
  ```
- Source → Sink 路径：`req.get('host')` / `req.hostname` → `State.serverHostname` → `makeLoginLink` → HTML 内嵌绝对 URL 与 `/connect` 302 Location。
- Why Vulnerable：无固定基域或 Host 白名单；攻击者伪造 Host 即可污染后台列出的浏览器登录链接与重定向。
- PoC 思路：
  ```bash
  curl -isk -H 'Host: attacker.test' \
    -H 'Cookie: <有效授权>' \
    --data 'ws_endpoint=5010' \
    https://victim-admin.example.com/connect
  ```
  返回的 `Location` 与页面锚点均为 `https://attacker.test:<port>/login?...`。
- 影响评估：管理员或脚本点击登录链接会被导向攻击域，泄露 token 或执行恶意操作，风险高。
- 修复：为部署面配置常量外链基址（如 `ADMIN_BASE_URL`），生成 URL 时改用该常量或相对路径；同时对 `req.hostname` 做白名单校验并限制可信代理。

### Finding #3：Socket-Puppet 服务登录链接可被 Host 污染（存在）
- File/Line：`src/services/pool/socket-puppet-service/src/server.js`:L295-L300, L328-L347, L432-L448
- Code Snippet：
  ```js
  function makeLoginLink({app_port,token}) {
    return `${GO_SECURE ? 'https' : 'http'}://${State.serverHostname}:${app_port}/login?token=${encodeURIComponent(token)}`;
  }
  …
  app.use((req, res, next) => {
    const newOrigin = `${req.protocol}://${req.get('host')}`;
    if ( req.hostname !== State.serverHostname ) {
      State.serverHostname = req.hostname;
    }
    next();
  });
  …
  res.redirect(connection.loginLink);
  ```
- Source → Sink 路径：`req.get('host')` / `req.hostname` → `State.serverHostname` → `makeLoginLink` → `/connect` 302 Location。
- Why Vulnerable：同样未固定基域或做 Host 校验，导致登录入口依赖可控 Host 头。
- PoC 思路：
  ```bash
  curl -isk -H 'Host: attacker.test' \
    -H 'Cookie: <有效授权>' \
    --data 'ws_endpoint=5010' \
    https://victim-socket.example.com/connect
  ```
  将得到攻击域名的登录链接。
- 影响评估：Socket 控制端的使用者会被导向恶意站点，可能泄露凭据或执行错误操作。
- 修复：同 Deploy 服务，固定登录 URL 的可信基域并引入 Host 白名单/可信代理限制。

### Finding #4：HTTP→HTTPS 重定向可被 Host 污染（存在）
- File/Line：`src/server.js`:L30-L35
- Code Snippet：
  ```js
  redirector.get('/*path', (req,res) => {
    res.redirect('https://' + req.headers.host + req.url);
  });
  ```
- Source → Sink 路径：`req.headers.host` → 字符串拼接 → `res.redirect`。
- Why Vulnerable：未校验 Host，HTTP 请求指定恶意 Host 会触发开放式重定向。
- PoC 思路：
  ```bash
  curl -i -H 'Host: attacker.test' http://victim-http.example.com/somepath
  ```
  `Location` 为 `https://attacker.test/somepath`。
- 影响评估：可用于开放重定向钓鱼或绕过部分安全策略。
- 修复：使用配置的受信任主机名（如 `HTTPS_BASE_HOST`）构造重定向，或校验 Host 白名单。

### Finding #5：登录失败页嵌入可控绝对 URL（存在）
- File/Line：`src/ws-server.js`:L482-L513
- Code Snippet：
  ```js
  res.type("html");
  res.status(401);
  …
  res.end(`Incorrect token. <a href=https://${req.hostname}/>Try again.</a>`);
  ```
- Source → Sink 路径：`req.hostname` → 插入 HTML 锚点。
- Why Vulnerable：`req.hostname` 受 Host 头控制，导致页面展示的“Try again”链接指向攻击域名。
- PoC 思路：
  ```bash
  curl -isk -H 'Host: attacker.test' https://victim.example.com/login?token=bad
  ```
  页面中的链接即指向 `https://attacker.test/`。
- 影响评估：虽然需要用户手动点击，但可辅助钓鱼并误导用户离开合法站点。
- 修复：改用固定可信域或改成相对链接 `/`，并配合 Host 白名单。

## Overall Verdict
存在多条 Host Header 污染链路，覆盖文档转换、部署/Socket 管理面及主站重定向，影响范围广、可被利用进行钓鱼和登录链接劫持，优先级 **High**。建议尽快落地固定外链基址、Host 白名单及可信代理配置。

## Appendix
- 未发现可信代理或 Host 白名单相关配置；如部署在反代后，建议结合框架中间件（如 `app.set('trust proxy', ...)` 或 Nginx `proxy_set_header Host`）与后端校验一并加固。
