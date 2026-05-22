---
title: AUTOSAR わかりにくいこと12
tags: AUTOSAR XML 制御 小川メソッド OSEK
author: kaizen_nagoya
---
AUTOSAR わかりにくいこと ~~10~~ ~~11~~ ~~13~~ 14 を開催します。

2004年頃から、AUTOSARを仕事で扱って、これまで約数千の質問をいただいて来ました。

半分以上が答えられていないかもしれません。
半分以上が嘘の答えをしたかもしれません。

ここでは、その反省に立って、答えられなかったり、嘘の答えをいった背景、状況、流れを記載してみます。

最初に書いた版は、思いついた順番でした。
そこで、
説明しやすい順番に並べ直してみました。

Requirement Specification
Driver Interface

|項目|初版|2版|現行|
|:----|:----|:----|:----|
|電子制御の時間制約記述|-|0|0
|port, signal, channel|8|1|1
|状態(state, mode)|9|2|2
|interface(module)|7|3|3
|interface(API)|-|-|4
|自然言語で記述|1|4|5
|一意な定義か並列な定義か|4|5|6
|XMLは銀の弾丸か|3|6|7
|通信規約とOSの対応|5|7|8
|ISO OSI参照|10|8|9
|ISO, IEC, ITUとの関係|6|9|10
|競争領域と協力領域|2|10|11
|ソフトウェア工学|11|11|12
|特許|||13
|IPC/RPC|-|-|14
|Vehicle API||15

並べ直して感じたことがあります。
AUTOSARのわかりにくさは、できない抽象的な目標を掲げていることかもしれません。
もう一つは、本当はできるとよい具体的なことができずにいることがあるかもしれません。

電子制御時間記述が十分ではないかもしれないため新たに追加した。
並べなおした最初の３つが具体的なこと、
次の３つが記述言語について、
次の３つが規格の関連について、
最後の２つが抽象的な事項にした。

いかがでしょうか。

<この項は書きかけです。順次追記します。>
This article is not completed. I will add some words in order.
# 0. 電子制御の時間制約記述。
自動車の電子制御は排ガス規制達成に始まっているらしい。
電子制御のためには、時間制約など、具体的ではなくても記述があるとよい。CANが電気的調停で時間制約を満たせたり、OSEKがOSが割り込みを邪魔しないことにより時間制約を満たせることについて記述がない。

2,0では、
Applying Simulink to AUTOSAR
という文書がある。
https://www.autosar.org/fileadmin/standards/classic/3-1/AUTOSAR_SimulinkStyleguide.pdf

モデルベース開発から全ソフトウェアを自動生成するための道筋を検討している。
その後、改定していない。Matlab/simulinkは、LLMMCPに対応している。

【Paper&Hacks #84】LLM and MCP on model based design
https://matsuolab-community.connpass.com/event/393459/

# 1. port, signal, channel
ハードウェアとソフトウェアで、port, signal, channelという同じ言葉を、別の意味に使っている。
例えば、physical port, rte port, TCP portなど修飾語をつければ区分できる。
省略している場合は、その文書がどちらよりの文書かで判断するとよい。
port driverとsws rte の目次に出てくる項目だと次のようである。

|software port|hardware port|
|:----|:----|
|sender receier port|port driver|
|client server port|port pin|
|port defined argument value|port init|
|mode port|port set pin direction|
|non identical port|port get version info|
|rte port| |
|rte nport| |

以下は、software portの用語だが、直感的にはどちらかわかりにくい。
softwareかなにか、頭につけてほしい。

port interface
unconnected port
port api section

短縮名(short name)で、複数の定義が共存していたりしているかもしれません。

overlapped definition in AUTOSAR short name. over 50.:英語(49)
https://qiita.com/kaizen_nagoya/items/9a171ee6a74163d128e9

# 2. 状態(state, mode)
状態をstateと呼んだり、modeと呼んだり、場合によってはphaseということもあるらしい。

AUTOSAR 状態遷移を網羅する(2.0版）
https://qiita.com/kaizen_nagoya/items/64535352b3f5f20e15ed

すべての状態遷移を状態遷移表(UML)で記載してみようと計画中。
CANだけで何種類もあることを確認。
全体で100種類くらいあることを想定。

# 3. interface(module)
ソフトウェアDriver以外に、インタフェースというモジュールがあるらしい。interfaceといえば、モジュールとモジュールの界面(iterface)を規定するものである。インタフェースがモジュールであれば、インタフェースというモジュールのインタフェースが必要なんじゃないかと疑問に感じる人がいるかもしれない。インタフェースはモジュールにしないのがソフトウェアの仕様なのではないのだろうか。
なんでinterfaceというモジュールを作る気になったのだろう。

version 2.0当時でもいらないと思ったのは、
CAN interface, FlexRay interface, LIN interface, Watchdog Interface.

# 4. interface(api)
# 5. 自然言語で記述
一部、UML、XMLなどでの記述があります。
仕様のほとんどを自然言語で書いています。

状態遷移をすべてUMLで記載していれば、まだよかったかもしれません。自然言語で記述し、仕様記述言語で書いてないAUTOSARのわかりにくさを代表するかもしれません。

文書として、Templateを作って内容を記述したり、
Metamodelを作ってModelを記述したりという仕組みはいろいろ作られています。
しかし、Templateを作って記述した内容の用語定義が整合性がなかったり、参考文献の整合性がなかったりしていては、見た目だけを揃えたということになってしまったかもしれません。

卒業研究は制御理論の研究室でモデル記述とその数値解析は得意でした。メタモデルは書いたことがなく、何のためにメタモデルを書くのかをりかいしていません。Metamodelは、実際のModel例がたくさんあれば、そのMetamodelの良さが確認しやすいかもしれません。Metamodelだけあって、実際のModel例がないと嬉しくないかもしれません。

# 6. 一意な定義か並列な定義か
ver. 2.0では、initiatorという提案者の名前を掲載するようにしていました。そのため、複数の提案者が別の仕様を提案していれば、一意な定義ではなく並列な定義であることはとても理解しやすかったような気がします。

その後、initiatorという項目を無くしてしまい、
定義が一意か並列かがわかりにくくなっています。

Autosar 2.0を読む
https://qiita.com/kaizen_nagoya/items/b44a1047c2c517d522fe

廃止した文書がないのもわかりにくくしているかもしれません。
何は規定していたのに辞めたのかがわからないと、２つを一つにしたのかどうかなど、手がかりが掴めないことがあります。せっかく原稿文書の過去のものはなるべく残すようにしていただいているのですから、廃止した全文書は廃止記載して残しておいていただけるとありがたい。

AUTOSAR文書の読み方（文書番号と発行年）
https://qiita.com/kaizen_nagoya/items/daa3f7de7e86b89bcc33

# 7. XMLは銀の弾丸か
Microsoft Excel, Wordが、OOXMLという共通の形式で記述し、
容易にC#などのプログラミング言語で扱えるようになったのは、
驚異的な変革だったかもしれません。

ISO/IEC 29500-1:2008
Information technology — Document description and processing languages — Office Open XML File Formats — Part 1: Fundamentals and Markup Language Reference

それは、Open Officeというライバルが、OpenDocumentという仕様を国際規格にして普及を促進しようとしたことへの対抗だったから成功したのかもしれません。
https://www.openoffice.org/ja/

ISO/IEC 26300:2006
Information technology — Open Document Format for Office Applications (OpenDocument) v1.0

このように、XMLは、Open化の標準化にとっては、中心的な役割を果たして来たと言えるかもしれません。

XML系のソフトウェアでは、編集作業中の整合性の確認には時間がかかりすぎること、複雑な定義ができるだめ無駄そうなデータを削ってもいいかどうかの判断が難しいこと、その結果、見た目には同じにみえるが内部でのデータの違うファイルの種類が数限りなくできる可能性があることなど、さまざまな課題があるかもしれません。

それに対して、json形式という単純なデータ構造は、
単純であるために整合性の確認に時間がかからず、
複雑な定義をしなくても処理が可能であることが習慣化し、
その結果、見た目とデータがそんなに乖離しないような気になる利点があるかもしれません。

XMLという選択はよい選択だったはずなのですが、
簡単な構造でよいものは簡単な構造にもできるという選択肢が
あってもよかったかもしれません。

# 8. 通信規約とOSの対応
CANとOSEKは、共存関係で発展してきました。
ちょうど, Ethernet, TCP/IP, UNIX(Linux)が発展してきたのと同じように。

FlexRayも、TTOSのような時刻同期に基づいたOSが提供できれば、うまくいったかもしれません。
通信規約側に時間に関する規定が豊富であれば、OS側に特に機能は要らないという考え方もあるようです。
バスガーディアンの標準化がうまくいかなかった時点で駄目になったとは思えません。
どこか１社でも、すごく安くICを出せば市場が立ち上がったのでしょうか。
ケーブルとコネクタが安くて、取り回しが容易ならよかったのでしょうか。
まだよくわかっていません。順次調査します。

AUTOSARのAdaptive PlatformとしてEthernet, TCP/IP, UNIX(linux)を採用したように。

はじめての車載Ethernet Q&A 16
https://qiita.com/kaizen_nagoya/items/81375e39d5255c479d0e

車載ネットワークの高速化
https://qiita.com/kaizen_nagoya/items/a8cee76395d7d6801f2e

# 9. ISO OSI参照
ISO OSIは、その仕様が大きすぎ、全体構造はわかるものの、それぞれの層の役割分担がわからない状態において、TCP/IPという Ethernet上の通信規約によって事実上亡き者にされたと思っていた。

AUTOSARの校正(calibration)関係の規定では、ISOのOSIをしばしば参照している。参照している文献名や発行年がいろいろ違っていて、何を参照したいかがわからないという面もある。

ISOのOSIが現代で役にたつとすれば、新たなセキュリティを強化するときの構造設計ではないだろうか。
AUTOSARの校正(calibration)がセキュリティを基盤に基本設計できているという記述は見当たっていない。ISO OSIを参照した理由がわかっていない。

AUTOSAR related Standard
https://qiita.com/kaizen_nagoya/items/13b163f8515615ecc648

# 10. ISO, IEC, ITUとの関係
WTO/TBT協定に基づき、国際的な技術仕様は、ISO,IEC,ITUの文書として発行することが基本的な行動様式になっています。

AUTOSARが始まった以降に、LIN, FlexRayはそれぞれISO規格になっています。

ISO 17458-1:2013
Road vehicles — FlexRay communications system — Part 1: General information and use case definition

ISO 17987-1:2016
Road vehicles — Local Interconnect Network (LIN) — Part 1: General information and use case definition
https://www.iso.org/standard/61222.html

FlexRay Consortium, Lin Consortiumからの提案で、
AUTOSARからの提案ではなさそうです。

ISO,IEC,ITUに国際規格を協調して提案している団体は多数あります。
Liaison(連絡）関係を結びます。
例えば、IEEEは、ISO/IEC JTC1とA Liaisonを結び、
ISO/IEC/IEEEで始まる国際規格を発行しています。
IEEEでまず発行してからISO/IECに持ち込むものもあれば、
ISO/IEC/IEEEで同時に審議する場合もあります。

AUTOSARとISO,IEC,ITUとLiaison関係を確認できていません。

MISRAは、ISO/IEC JTC1/SC22/WG14などとC Liaisonを結び、
定期的に意見文書を発行しています。

MISRA C Liaison Report to ISO/IEC JTC1/SC22/WG14 21st-25th October 2019
http://www.open-std.org/jtc1/sc22/wg14/www/docs/n2445.pdf

# 11. 競争領域と協力領域

何が競争領域かは、日々変わっていきます。
合意で決められるものではないという経験則があります。

相手を出し抜くことが競争なのかもしれません。
全員が合意しても、破ったときの罰則条項以上の利益があれば、
合意を破るのが経済原則ではないのでしょうか。

例えば、OEM（自動車製造・販売業）だけでも、事前に何が協力領域で、何が競争領域かを決められません。
OEM（自動車製造・販売業）と部品製造業の間では、さらに複雑で競争領域と協力領域は日々変化する可能性があります。

OEMと部品製造業と半導体会社の間は、もっと複雑でしょう。

さらに、モデル記述するMatlabのモデルからコード生成を提供する Mathworks, 
CANの通信シミュレータCANoeを提供するvector,
UMLからコード生成するEnterPrise Architectを提供するSparxsystemsなどのツールベンダ間および顧客間には、もっともっと複雑な利害関係が存在しているかもしれません。

# 12 ソフトウェア工学
ソフトウェア工学の教科書に、一人の設計者が書き下ろさないと、
よい設計にはならないという趣旨のことを書いてあったような気がする。

人月の神話―狼人間を撃つ銀の弾はない (Professional computing series (別巻3))フレデリック・P. Jr. ブルックス

<img width="250" alt="51TWX1TAERL._SX327_BO1,204,203,200_.jpg" src="https://qiita-image-store.s3.ap-northeast-1.amazonaws.com/0/51423/e1eb0ca8-0892-3253-78bb-3d1a98b75d22.jpeg">

https://bookmeter.com/books/105264

# 13 特許
ISO, IECの国際規格は、特許条項があり、規格に関連する特許保持者が、公平な扱いをすることを宣言しないと規格は発行しない。

AUTOSAR仕様に関する特許がどうなっているかの記載がないとわかりにくいかもしれない。

# 14 IPC/RPC
# Vehicle API
# 回答の記録
回答が嘘と書いたのは、ここに書いた１2項目について、何らかの考えが安定していない方には、嘘のように思えるという事態を含んでいます。
それを避けるために、口頭で回答したことは、回答したら結果を電子的にあとで送ってとか、GitlabのprivateのWikiに記載してと頼んでいます
半分程度の方は記録してもらえない。

いくつかの会社の方、技術者の方は適切に対応してくださっています。ありがとうございます。

# 参考資料
「自動車の故障診断に関連するプログラマーになりたての方が参照するとよさそうな情報」の読み方
https://qiita.com/kaizen_nagoya/items/0c6b8373f93ce52def33

「ソフトウェアエンジニアが「トヨタ」の伝統を革新して、ソフトとハードの融合した「モノづくり」を推進する時代へ」Qiita Zine記事を読み解く
https://qiita.com/kaizen_nagoya/items/20a3144e0ccd4d3655b5

AUTOSAR関連「TOPPERS 開発者会議」資料集
https://qiita.com/kaizen_nagoya/items/45266736d1291e1c1e7e

word count autosar 20-11
https://qiita.com/kaizen_nagoya/items/e9b9dec105527aac3801

AUTOSAR教材作成３年計画
https://qiita.com/kaizen_nagoya/items/84d8f1ecbbe7af7803af

TOPPERS のAUTOSARへの貢献(更新中)
https://qiita.com/kaizen_nagoya/items/d363cf06e2176207b391

統計と確率　プログラマによる、プログラマのための、統計と確率のプログラミングとその後
https://qiita.com/kaizen_nagoya/items/6e9897eb641268766909

QC検定に落ち「たか」らかける記事。20,000人の方に読んでいただけ「たか」ら書ける記事。「たかたか」分析の勧め。
https://qiita.com/kaizen_nagoya/items/2a371ee8c8f1b78cd5bb

Qiita(28)画像の大きさ調整
https://qiita.com/kaizen_nagoya/items/cef6ae1fcbdbec9e7be2

## 一覧
物理記事　上位100
https://qiita.com/kaizen_nagoya/items/66e90fe31fbe3facc6ff

量子(0) 計算機, 量子力学 
https://qiita.com/kaizen_nagoya/items/1cd954cb0eed92879fd4

数学関連記事１００
https://qiita.com/kaizen_nagoya/items/d8dadb49a6397e854c6d

言語・文学記事　１００
https://qiita.com/kaizen_nagoya/items/42d58d5ef7fb53c407d6

医工連携関連記事一覧
https://qiita.com/kaizen_nagoya/items/6ab51c12ba51bc260a82

自動車　記事　１００
https://qiita.com/kaizen_nagoya/items/f7f0b9ab36569ad409c5

通信記事１００
https://qiita.com/kaizen_nagoya/items/1d67de5e1cd207b05ef7

日本語（０）一欄
https://qiita.com/kaizen_nagoya/items/7498dcfa3a9ba7fd1e68

英語(0) 一覧
https://qiita.com/kaizen_nagoya/items/680e3f5cbf9430486c7d

転職(0)一覧
https://qiita.com/kaizen_nagoya/items/f77520d378d33451d6fe

仮説（0）一覧（目標100現在40）
https://qiita.com/kaizen_nagoya/items/f000506fe1837b3590df

Qiita(0)Qiita関連記事一覧（自分）
https://qiita.com/kaizen_nagoya/items/58db5fbf036b28e9dfa6

鉄道（０）鉄道のシステム考察はてっちゃんがてつだってくれる
https://qiita.com/kaizen_nagoya/items/26bda595f341a27901a0

安全（0）安全工学シンポジウムに向けて: 21
https://qiita.com/kaizen_nagoya/items/c5d78f3def8195cb2409

一覧の一覧( The directory of directories of mine.) Qiita(100)
https://qiita.com/kaizen_nagoya/items/7eb0e006543886138f39

Ethernet 記事一覧　Ethernet(0)
https://qiita.com/kaizen_nagoya/items/88d35e99f74aefc98794

Wireshark 一覧 wireshark(0)、Ethernet(48) 
https://qiita.com/kaizen_nagoya/items/fbed841f61875c4731d0

線網（Wi-Fi）空中線(antenna)(0) 記事一覧(118/300目標)
https://qiita.com/kaizen_nagoya/items/5e5464ac2b24bd4cd001

OSEK OS設計の基礎　OSEK(100)
https://qiita.com/kaizen_nagoya/items/7528a22a14242d2d58a3

Error一覧 error(0)
https://qiita.com/kaizen_nagoya/items/48b6cbc8d68eae2c42b8

プログラマによる、プログラマのための、統計(0)と確率のプログラミングとその後
https://qiita.com/kaizen_nagoya/items/6e9897eb641268766909

官公庁・学校・公的団体（NPOを含む）システムの課題、官（０）
https://qiita.com/kaizen_nagoya/items/04ee6eaf7ec13d3af4c3

「はじめての」シリーズ　 ベクタージャパン　
https://qiita.com/kaizen_nagoya/items/2e41634f6e21a3cf74eb

AUTOSAR(0)Qiita記事一覧, OSEK(75)
https://qiita.com/kaizen_nagoya/items/89c07961b59a8754c869

プログラマが知っていると良い「公序良俗」
https://qiita.com/kaizen_nagoya/items/9fe7c0dfac2fbd77a945

LaTeX(0) 一覧　
https://qiita.com/kaizen_nagoya/items/e3f7dafacab58c499792

自動制御、制御工学一覧（０）
https://qiita.com/kaizen_nagoya/items/7767a4e19a6ae1479e6b

Rust(0) 一覧　
https://qiita.com/kaizen_nagoya/items/5e8bb080ba6ca0281927

小川清最終講義、最終講義（再）計画, Ethernet(100) 英語(100) 安全(100)
https://qiita.com/kaizen_nagoya/items/e2df642e3951e35e6a53

＜この記事は個人の過去の経験に基づく個人の感想です。現在所属する組織、業務とは関係がありません。＞
This article is an individual impression based on the individual's experience. It has nothing to do with the organization or business to which I currently belong.
#### 文書履歴(document history)
ver. 0.01 初稿 6項目 20210529 
ver. 0.02 11項目 20210530 午前
ver. 0.03 並び替え 20210530 午後
ver. 0.04 少し並び替え解説追記 20210530 夕方
ver. 0.05 電子制御の時間制約記述 追記 20210530夜
ver. 0.06 車載Ethernet 追記 20210808
### 最後までおよみいただきありがとうございました。
いいね　💚、フォローをお願いします。
#### Thank you very much for reading to the last sentence.
Please press the like icon 💚　and follow me for your happy life.
