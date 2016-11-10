from RIPProtocol import RIPFactory, RIPServerFactory
from KISSLayer import KissFactory, KissServerFactory


ConnectFactory = RIPFactory.StackType(KissFactory)
ListenFactory = RIPServerFactory.StackType(KissServerFactory)