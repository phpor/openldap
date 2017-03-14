## 基于 Openldap 2.4.39, 添加了动态码验证功能

##用法##

1. 设置环境变量 AUTH_URL 
2. url符合的接口规范：
   “username=%s&code=%s&app=ldap&ip=1.1.1.1”

   返回值：

   -- 成功： {"retcode":2000000}

   -- 失败： {"retcode": 错误码， "msg": "错误信息"}
