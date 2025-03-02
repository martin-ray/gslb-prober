# gslb-prober
A prober for using with DNS server to make upgrade it to GSLB


# TODO
- [x] HCタイプを充実させる。（現在はHTTPレイヤーのみ。TCPと、pingでのHCを実装したい。）
- [x] HCの結果をどうにかしてプロメテウス形式でエクスポートしたい。（どうやるのか）
- [ ] UIを完成させる
- [ ] zoneファイルを毎秒書き換えているが、ぶっちゃけこれはGSLB_Domainに何かしらの変更が加わった時で問題ない。なので、変更があったかなかったかを確認し、なかった場合はskipする処理を入れたい。
- [ ] 新しいEPが追加されるたびにyamlファイルとしてエクスポートされるようにしたい。
- [ ] (coreDNSの話だが)複数のネームサーバ間でゾーンファイルが共有されるようにしたい。(nfs？自前実装？？マジでムズイ。skydns形式だったらetcdが使えるのだけれども)


# setting
hc_type: 
  0: http
  1: https
  2: tcp
  3: icmp