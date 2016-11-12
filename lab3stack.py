import sys
try:
    sys.path.append("~/Documents/GitRepo/en600424lab2/src/")
except: print("\033[91mCouldn't find KISS and RIP where Fady put it. So you're probably not Fady.\033[0m")

from rip.RIPProtocol import RIPFactory, RIPServerFactory
from kiss.KISSLayer import KissFactory, KissServerFactory


ConnectFactory = RIPFactory.StackType(KissFactory)
ListenFactory = RIPServerFactory.StackType(KissServerFactory)