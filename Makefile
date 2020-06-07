JCC = javac
JFLAGS = -g
.SUFFIXES: .java .class

SRCDIR=src
BINDIR=bin
DOCDIR = doc

$(BINDIR)/%.class:$(SRCDIR)/%*java
	$(JCC) -d $(BINDIR)/ -cp $(BINDIR) $<


CLASSES= ClientLogger.class Encryption.class AsymmetricEncryption.class SymmetricEncryption.class Client.class ClientMain.class 
CLASS_FILES=$(CLASSES:%.class=$(BINDIR)/%.class)

default: $(CLASS_FILES)

doc:
	javadoc -d $(DOCDIR) $(SRCDIR)/*.java

clean:
	$(RM) $(BINDIR)/*.class
	$(RM) -Rf doc
