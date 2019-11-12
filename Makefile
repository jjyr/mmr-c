CC := cc
CFLAGS := -Ideps

test: test_runner
	./test_runner

test_runner: test_runner.c mmr.h
	$(CC) $(CFLAGS) -o $@ $<
