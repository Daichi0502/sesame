# SesameAPIの公式のdocument
# https://doc.candyhouse.co/ja/SesameAPI
#
# PythonのドキュメントをRubyに置き換えた。
# -------------------------------------------
# import datetime, base64, requests, json
# from Crypto.Hash import CMAC
# from Crypto.Cipher import AES
#
# uuid = '3DE4DE72-AAF9-25C1-8D0F-C9E019BB060C'
# secret_key = '2ebc2c087c1501480834538ff72139bc'
# api_key = 'SrSOEY9mBe6Ndl7bwyVPs5TsTPFTEq9tra8Occad'
#
# cmd = 88  # 88/82/83 = toggle/lock/unlock
# history = 'test5'
# base64_history = base64.b64encode(bytes(history, 'utf-8')).decode()
#
# print(base64_history)
# headers = {'x-api-key': api_key}
# cmac = CMAC.new(bytes.fromhex(secret_key), ciphermod=AES)
#
# ts = int(datetime.datetime.now().timestamp())
# message = ts.to_bytes(4, byteorder='little')
# message = message.hex()[2:8]
# cmac = CMAC.new(bytes.fromhex(secret_key), ciphermod=AES)
#
# cmac.update(bytes.fromhex(message))
# sign = cmac.hexdigest()
# # 鍵の操作
# url = f'https://app.candyhouse.co/api/sesame2/{uuid}/cmd'
# body = {
#     'cmd': cmd,
#     'history': base64_history,
#     'sign': sign
# }
# res = requests.post(url, json.dumps(body), headers=headers)
# print(res.status_code, res.text)
# ---------------------------------------------
#
module Sesame
  class KeyOperation
    attr_accessor :cmd, :store

    # api_keyは下記URLから取得する。403エラーの時は、新しく取得してみる。
    # https://partners.candyhouse.co/login/
    API_KEY = "api_keyの文字列"

    def initialize(cmd:, smart_lock:)
      @cmd = cmd
      @smart_lock = smart_lock
    end

    def execute
      uuid = @smart_lock.sesame_uuid
      secret_key = @smart_lock.sesame_secret_key
      history = @smart_lock.sesame_name
      base64_history = Base64.encode64(history)

      # 16進数のsecret_keyをバイナリーデータに変換する
      # bytes.fromhex(secret_key) -> [secret_key].pack("H*")
      cmac = OpenSSL::CMAC.new('AES', [secret_key].pack("H*"))

      # SECONDS SINCE JAN 01 1970. (UTC) unixtime
      timestamp = Time.current.to_i

      # uint32 (little endian) バイナリーデータに変換する
      # to_bytes(4, byteorder='little') -> pack("I*")
      message = [timestamp].pack("I*")

      # remove most-significant byte バイナリーデータを16進数文字列に戻す
      # hex()[2:8] -> unpack("H*") & slice(2..8)
      message = message.unpack("H*")
      message = message[0].slice(2..8)

      # bytes.fromhex(message) -> [message].pack("H*")
      cmac = cmac.update([message].pack("H*"))

      # hexdigest -> digest & unpack("H*")
      sign = cmac.digest
      sign = sign.unpack("H*") # バイナリーデータを16進数文字列に戻す

      body = {
        cmd: cmd,
        history: base64_history,
        sign: sign[0] # signは配列で保存されている
      }

      connection = Faraday::Connection.new("https://app.candyhouse.co/api/sesame2/#{uuid}/cmd")

      response = connection.post do |req|
        req.headers['X-API-KEY'] = API_KEY
        req.body = body.to_json
      end
    end
  end
end
