
DEBUG = True
DEBUGinst = True
def loginst(*argv):
    if DEBUG and DEBUGinst:
        print(argv)

def log(*argv):
    if DEBUG:
        print(argv)
