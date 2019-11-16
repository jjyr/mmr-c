CC := cc
CFLAGS := -O3 -Itest_deps

test: test_runner
	./test_runner

test_runner: test_runner.c mmr.o
	$(CC) $(CFLAGS) -o $@ $^

mmr.o: mmr.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm mmr.o
	rm test_runner
