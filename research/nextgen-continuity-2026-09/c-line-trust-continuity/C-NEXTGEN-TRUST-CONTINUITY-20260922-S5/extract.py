import urllib.request,re,html
from html.parser import HTMLParser
urls={
'klease':'https://kubernetes.io/docs/concepts/architecture/leases/',
'kapi':'https://kubernetes.io/docs/reference/using-api/api-concepts/',
'temporal':'https://docs.temporal.io/activities',
'awsconn':'https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html',
'awsstop':'https://docs.aws.amazon.com/step-functions/latest/apireference/API_StopExecution.html',
'azure':'https://learn.microsoft.com/en-us/rest/api/storageservices/lease-blob',
}
class P(HTMLParser):
 def __init__(self): super().__init__(); self.a=[];self.skip=0
 def handle_starttag(self,t,attrs):
  if t in ('script','style','noscript','svg'):self.skip+=1
 def handle_endtag(self,t):
  if t in ('script','style','noscript','svg') and self.skip:self.skip-=1
 def handle_data(self,d):
  if not self.skip:self.a.append(d)
for n,u in urls.items():
 try:
  raw=urllib.request.urlopen(u,timeout=40).read(); p=P();p.feed(raw.decode('utf-8','ignore')); text=' '.join(' '.join(p.a).split())
  open('/tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S5/'+n+'.txt','w').write(text)
  print(n,len(text))
  for term in ['resourceVersion','409','conflict','leaseDuration','renew','heartbeat','timeout','retry','StopExecution','callback','lease ID','lease ID']:
   i=text.lower().find(term.lower())
   if i>=0:print(' ',term, text[max(0,i-240):i+600])
 except Exception as e:print(n,e)
