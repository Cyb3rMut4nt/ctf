
## 诚韬战队诚韬战队诚韬战队诚韬战队诚韬战队
from qcloud_cos import CosConfig
from qcloud_cos import CosS3Client
import sys
import logging

# 正常情况日志级别使用INFO，需要定位时可以修改为DEBUG，此时SDK会打印和服务端的通信信息
logging.basicConfig(level=logging.INFO, stream=sys.stdout)


secret_id = 'AKIDQTmDJN64fKgXaWP7ugNMbwUtXApNt6jFT26SZL_zPW_6rf3DeluJH2WRXBpT6UpT'     
secret_key = 'a5eeIfrH4mjioFx6WorYagRmNhrcJGwsGlsKR6yCUPs='   
region = 'ap-shanghai'     
token = 'pZb05vy8ybYKofhYJSUb0yaqovcc7ita497ceb84ddf7e8e9c41751b3be6176b4wkBL7VaoJyILBzpxJ6ohZjPFBCX8SjAjorPfBPsESfHRP-ObzpT0c9yx_4bFpD3WcEIHzq4cSFmgV8Xgh7T1aFswJwVpoMdygnld8ag3VLFWfLMUK32dVkFAtF81Uuy24A3AY-mu11oWenjyAjdGH9M1V-d9DVswwakK_JibXY904RslvCNgSmiOwfnwDFBCwKM_BuO2yCL0HMAYz8hxUeiNYGwfLbx5Jh6BDWdSm0Qu3E1sel8sqr-e1jSseOi07T7ziirGTbiII9_536QaNG_rlN5BXDM8YWw8eTogYbYxIzlWRVtB7vRt0i34HzXMeTnzyof1s6as1o9z-PdgEg'             
scheme = 'http'

config = CosConfig(Region=region, SecretId=secret_id, SecretKey=secret_key, Token=token, Scheme=scheme)
client = CosS3Client(config)

response = client.list_objects(
    Bucket='gwb2021-1301911158',
    Prefix=''
)
print(response)
