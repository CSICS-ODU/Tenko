import requests
import random
import string,pdb,traceback


url = 'http://34.135.203.85:7654/api/scores'
# url = 'http://192.168.121.138:7654/api/scores'
# url = 'http://192.168.203.161:7654/api/scores'
# url = 'http://192.168.251.17:7654/api/scores'

def request_builder_old(scores, addScore = False):
    letters     = string.ascii_lowercase
    transaction_id = 'IDS'.join(random.choice(letters) for i in range(4))
    if addScore:
      mode = "addScore"
    else:
      mode = "getScore"
    data = "{\"id\":\""+str(transaction_id)+"\",\n\"execer\": \"admin:admin\",\"messageType\": \""+mode+"\",\n\"digsig\": \"\"" 
   
    if addScore:
      for score in scores:      
        data += ",\n\"userId\": \""+str(score[0])+"\",\"numerator\":" +str(score[1])+",\"denominator\":" +str(score[2])       
    else:
      data += ",\n\"userId\": \""+str(scores[0][0])+"\""
    data += "}"  
    return data  



def request_builder(scores, timestamp, addScore = False):
    letters     = string.ascii_lowercase
    unique      = ''.join(random.choice(letters) for i in range(4))
    
    if addScore:
      mode = "addScore"
    else:
      mode = "getScore"
    data = "[\n"
    for score in scores:
      transaction_id = 'IDS'+unique+'_'+str(score[0])+'_'+str(timestamp)
      # print(transaction_id)
      # pdb.set_trace()

      data += "{\n\"id\":\""+str(transaction_id)+"\",\n\"execer\": \"admin:admin\",\n\"messageType\": \""+mode+"\",\n\"digsig\": \"\""     
      if addScore:
        data += ",\n\"userId\": \""+str(score[0])+"\",\n\"numerator\":" +str(score[1])+",\n\"denominator\":" +str(score[2])       
      else:
        # pdb.set_trace()
        data += ",\t\"userId\": \""+str(score)+"\""
      data += "\n},"
    data = data[:-1]
    data += "\n]" 

    if  len(scores)==1:
      data=data[1:-1]
    return data  

header = {"Content-Type": "application/json", "Bearer": "eyJkaWdzaWciOiJORWpYZnIwQjJMZG4ySGxPb2t5blp0dkNzSFVqMGFoVTVZd1F5TmJSVCtOYjlwTnBXcEsvUi9UbDZpanhPVVJiVlJHc2NHaFIrcWVCbkZhK09YYjBmMGlacVh0WHBDVXV6bnJOcTFKRmpGZC8zSU80L1o4SXl3WG1EdWFGcUg5Njc5VE9neVRkcU1nT01VeWNNWTF0bmtIUStWVUtUN0JTV0NWMEM3ZmNXbEE9IiwiaWQiOiJlcmFuZ2FlYkBnbWFpbC5jb20iLCJpc3N1ZVRpbWUiOjE1NTg0ODk4ODksInJvbGVzIjoiIiwidHRsIjo2MH0="}

# header= {header1,header2}

a = ['aaa',5.12,5.61]
b = ['aab',4.15,4.17]
c = ['192.168.2.13',9.02,10.41]

# scores = [a,c]
# save = request_builder(scores, 1, True)
# print(save ,'\n')
# # save = request_builder_old(scores, True)

# try:
#   response = requests.post(url, data=save, headers=header)
#   print(response.json(),'\n')
# except Exception as e:
#   print(e)
#   traceback.print_exc()
#   print('\n')
#   try:
#     print(response.content)
#   except Exception as e:
#     print(e)
#   pdb.set_trace()



scores = [c[0]]
print (c[0])

print("lookup\n\n")

lookup = request_builder([scores[0]], 1)
print(lookup,'\n' )
response = requests.post(url, data=lookup)
try:
  print(response.json(),'\n')
except Exception as e:
  print(e)
  traceback.print_exc()
  print('\n')
  try:
    print(response.content)
  except Exception as e:
    print(e)
  pdb.set_trace()


# lookup = request_builder([scores[1]], 3)
# print(lookup ,'\n')
# response = requests.post(url, data=lookup)
# print(response.json(),'\n')

# lookup = request_builder([scores[2]], 5)
# print(lookup,'\n')
# response = requests.post(url, data=lookup)
# print(response.json(),'\n')