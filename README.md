# exeinfo

## in English
print exe-file header

## 日本語で
MS-DOSなどのEXEファイルのヘッダの内容を表示するrubyのプログラムです。

### exeinfo
#### 対象のEXEファイルを指定
対象のEXEファイルを指定しただけだと単純にヘッダの情報を表示します。

#### オプション t
ヘッダの情報だけでなく、リロケーションテーブルの情報も表示します。

#### オプション r
オプション t で表示する情報に加えて、以下の情報も表示します。
- ヘッダとリロケーションテーブルの間にある領域
- リロケーションテーブルとロードモジュールの間にある領域

### exeheaderparser
exeinfoの肝となる機能を実現している部分です。ライブラリ的に使えるかと思います。
