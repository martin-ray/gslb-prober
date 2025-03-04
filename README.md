# gslb-prober
A prober for using with DNS server to make upgrade it to GSLB


# TODO
- [x] HCタイプを充実させる。（現在はHTTPレイヤーのみ。TCPと、pingでのHCを実装したい。）
- [x] HCの結果をどうにかしてプロメテウス形式でエクスポートしたい。（どうやるのか）
- [x] zoneファイルを毎秒書き換えているが、ぶっちゃけこれはGSLB_Domainに何かしらの変更が加わった時で問題ない。なので、変更があったかなかったかを確認し、なかった場合はskipする処理を入れたい。
- [x] prometheusのダッシュボードを作る [public dashboard](https://grafana.ingenboy.com/public-dashboards/22647c34b9604b259c61ef1fe797f230)
- [x] 新しいEPが追加されるたびにyamlファイルとしてエクスポートされるようにしたい。
- [ ] 現在はAレコードしか張れないが、cnameも張れるようにした方がいい？いやー、まあ機能としてはあってもいいともうけど、ほぼ十はないな。逆にcnameを張ってもらう側だからな。
- [ ] UIを完成させる (いったんapiだけでいいかなーとなった)
- [ ] (coreDNSの話だが)複数のネームサーバ間でゾーンファイルが共有されるようにしたい。(nfs？自前実装？？マジでムズイ。skydns形式だったらetcdが使えるのだけれども)


# setting
hc_type: 
  0: http
  1: https
  2: tcp
  3: icmp

# API request examples

## List all domains and endpoints

```
curl http://ns02.workers-bub.com:8089/v1/domain/list | jq .
```
make the response json tidy by using jq command. 


## create domain

```
curl -X POST "http://162.43.53.234:8089/v1/domain/add"      -H "Content-Type: application/json"      -d '{
        "DomainName": "exmaple",
        "Endpoints": [
          {
            "IP": "162.43.29.213",
            "PORT": 443,
            "HOST_HEADER": "umurphy.com",
            "HCPath": "",
            "IsHealthy": true,
            "HCType": 2
          }
        ],
        "HCIntervalSec": 2,
        "TimeoutSec": 5,
        "Password": "supersecret",
        "TTL": 5
     }'
```

## add new EP to domain
assume exmaple(.workers-bub.com) is already added to the GSLB doamin

```
curl -X POST "http://162.43.53.234:8089/v1/domain/add"      -H "Content-Type: application/json"      -d '{
        "DomainName": "exmaple",
        "Endpoints": [
          {
            "IP": "162.43.29.213",
            "PORT": 443,
            "HOST_HEADER": "umurphy.com",
            "HCPath": "",
            "IsHealthy": true,
            "HCType": 2
          }
        ],
        "HCIntervalSec": 2,
        "TimeoutSec": 5,
        "Password": "supersecret",
        "TTL": 5
     }'
```
ensure the Password is same as the one you registered when creating the domain.


## delete domain
assume exmaple(.workers-bub.com) is the existing GSLB doamin

```
curl -X POST "http://162.43.53.234:8089/v1/domain/delete"      -H "Content-Type: application/json"      -d '{
        "DomainName": "exmaple",
        "Password": "supersecret"
     }'
```
ensure the Password is same as the one you registered when creating the domain.