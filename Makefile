.PHONY : test clean

test: tttt.c
	gcc -g -Wall -o $@ $^ -lpthread

clean:
	rm -f test


