certdir = "/home/fady/Documents/certs/signed_certs/"
class CertFactory:

    
    @staticmethod
    def getPrivateKeyForAddr(addr):
        with open(certdir+addr+"pk") as f:
            return f.read()
    
    @staticmethod
    def getCertsForAddr(addr):
        chain = []
        with open(certdir+addr+"cert") as f:
            chain.append(f.read())
        with open(certdir+"1337cert") as f:
            chain.append(f.read())
        return chain
    
    @staticmethod
    def getRootCert():
        return open(certdir+"rootcert").read()
