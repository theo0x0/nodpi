from dnslib.server import DNSServer, BaseResolver
from dnslib.dns import DNSRecord, RR, QTYPE, A, DNSQuestion
import asyncio
from nodpi import is_blocked, local_ip

def resolve(host, server):
    q = DNSRecord()
    q.add_question(DNSQuestion(host))
    
    for r in DNSRecord.parse(q.send(server, timeout=5)).rr:
        if r.rtype == 1:
            return str(r.rdata)



class LocalResolve(BaseResolver):
    def resolve(self,request,handler):
        
        q = str(request.questions[0].qname)
        
        if is_blocked(q):
            res = request.reply()
            res.add_answer(RR(request.questions[0].qname,QTYPE.A,rdata=A(local_ip),ttl=60))
            
            return res
        
        return DNSRecord.parse(request.send("9.9.9.9"))

