all: nfqnl_practice

nfqnl_practice: nfqnl_practice.c
	gcc -o nfqnl_practice nfqnl_practice.c -lnetfilter_queue

clean:
	rm -f nfqnl_practice *.o