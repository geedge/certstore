[目录层次介绍]
1. conf		配置文件目录
2. make		Makefile配置文件目录
3. release	执行make tarball后生成的安装包文件
4. src		源代码目录
5. ca		根证书目录
src/components    使用的静态库所需的头文件（libevent、openssl、hiredis）
src/inc           系统所需头文件
src/lib           静态库
src/package       安装包临时目录
src/rt            公共函数

[编译运行]
1. cd src && make
2. ./cert_store --normal<--normal|--daemon>
备注：
发送请求命令：curl -X GET "x.x.x.x:9995/ca?host="www.qq.com"&flag=1&valid=1" -m 30 -v
使用--daemon运行时，配置文件中使用绝对路径

[安装包使用]
1. cd src && make tarball
2. cd release 
3. tar -zxvf cert_store-1.0.1.0.tar.gz
4. cd cert_store-1.0.1.0 && make install