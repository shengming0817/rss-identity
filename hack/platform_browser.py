"""Controlled external-browser T2 fixture; never included in a runtime image."""
import http.cookiejar
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

root=Path(__file__).parent
opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(root/'ca.pem'))),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def get(url):
    try:return opener.open(url,timeout=10)
    except urllib.error.HTTPError as response:
        if response.code!=303:raise
        return response

start=get(sys.argv[1]);authorize=start.headers['Location'];start.close()
response=get(authorize);upstream=response.headers['Location'];response.close()
state=urllib.parse.parse_qs(urllib.parse.urlsplit(upstream).query)['state'][0]
u=urllib.parse.urlsplit(authorize)
callback=urllib.parse.urlunsplit((u.scheme,u.netloc,'/api/v1/oidc/callback',urllib.parse.urlencode({'state':state,'code':'platform-subject','iss':'https://idp.example.test'}),''))
response=get(callback)
if any('__Host-identity-session=' in value for value in response.headers.get_all('Set-Cookie',[])):raise RuntimeError('browser received central session')
redirect=response.headers['Location'];response.close()
if not redirect.startswith('http://127.0.0.1:'):raise RuntimeError('callback lost native binding')
get(redirect).close()
