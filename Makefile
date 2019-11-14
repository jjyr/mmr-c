CC := cc
CFLAGS := -Itest_deps

test: test_runner
	./test_runner

test_runner: test_runner.c mmr.o
	$(CC) $(CFLAGS) -o $@ $^

mmr.o: mmr.c
	$(CC) -c -o $@ $<
