
DEBUG = False
DEBUGinst = False
DEBUGresult = True
DEBUGcall = False
def loginst(*argv):
    if DEBUGinst:
        print(argv)

def log(*argv):
    if DEBUG:
        print(argv)
        
def logresult(*argv):
    if DEBUGresult:
        print(argv)
def logcall(*argv):
    if DEBUGcall:
        print(argv)
