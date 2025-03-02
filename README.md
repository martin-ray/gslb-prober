# gslb-prober
A prober for using with DNS server to make upgrade it to GSLB


# TODO
- [ ] HCタイプを充実させる。（現在はHTTPレイヤーのみ。TCPと、pingでのHCを実装したい。）
- [ ] HCの結果をどうにかしてプロメテウス形式でエクスポートしたい。（どうやるのか）
- [ ] UIを完成させる
- [ ] 新しいEPが追加されるたびにyamlファイルとしてエクスポートされるようにしたい。
- [ ] (coreDNSの話だが)複数のネームサーバ間でゾーンファイルが共有されるようにしたい。(nfs？自前実装？？マジでムズイ。skydns形式だったらetcdが使えるのだけれども)