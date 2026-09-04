/* NFT Forward 登录页 —— 独立脚本（从内联块移出，便于收紧 CSP） */
'use strict';
(function () {
  if (location.search.indexOf('error') !== -1) {
    var e = document.getElementById('err');
    if (e) e.textContent = '令牌错误，请重试';
  }
})();
