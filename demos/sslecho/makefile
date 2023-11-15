PROG ?= sslecho
NEWPROG ?= echecho

all: $(PROG) $(NEWPROG)

# Debug version.
#
$(PROG): main.c

	$(CC) -O0 -g3 -W -Wall -I../../include -L../../ -o $(PROG) main.c -lssl -lcrypto

$(NEWPROG): echecho.c
	$(CC) -O0 -g3 -W -Wall -I../../include -L../../ -o $(NEWPROG) echecho.c -lssl -lcrypto

test:

clean:
	rm -rf $(PROG) $(NEWPROG) *.o *.obj
