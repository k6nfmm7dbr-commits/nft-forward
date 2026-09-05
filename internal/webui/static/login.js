/* 登录页脚本 —— 独立文件（无内联脚本，配合严格 CSP default-src 'self'）。
 *
 * 只做一件事：登录失败后 URL 带 ?error=1 时显示提示。
 * 令牌只经 POST 表单提交，绝不写入 localStorage / sessionStorage / URL。
 */
'use strict';
(function () {
  if (location.search.indexOf('error') !== -1) {
    var e = document.getElementById('err');
    if (e) e.textContent = '令牌错误，请重试';
  }
})();
