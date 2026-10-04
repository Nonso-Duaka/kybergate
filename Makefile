# kybergate build file
#
#   make            build the three Kyber shared libraries the Python code loads
#   make kat        run the official pq-crystals self-tests + known-answer vectors
#   make vendor     rebuild the browser ML-KEM bundle (needs Node.js)
#   make test       pytest suite (unit, protocol, cross-implementation)
#   make e2e        drive the website in Chromium with Playwright (starts its own server)

KYBER   := third_party/pq-crystals-kyber
REF     := $(KYBER)/ref
LIBDIR  := kybergate/_native
PY      ?= .venv/bin/python
CC      ?= cc
CFLAGS  ?= -O3 -fomit-frame-pointer -Wall -Wextra
SRC     := kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c \
           fips202.c symmetric-shake.c randombytes.c
SRCS    := $(addprefix $(REF)/,$(SRC))
LEVELS  := 512 768 1024
LIBS    := $(foreach n,$(LEVELS),$(LIBDIR)/libkyber$(n).so)

k_512  := 2
k_768  := 3
k_1024 := 4

.PHONY: all kat vendor test e2e clean

all: $(LIBS)

$(LIBDIR)/libkyber%.so: $(SRCS)
	@mkdir -p $(LIBDIR)
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=$(k_$*) $(SRCS) -o $@

kat:
	$(PY) -m kybergate.kat

vendor:
	cd tools/vendor && npm install --no-audit --no-fund && npm run build

test: all
	$(PY) -m pytest

e2e:
	$(PY) tests/e2e/run_e2e.py

clean:
	rm -rf $(LIBDIR) build .pytest_cache
	$(MAKE) -C $(REF) clean >/dev/null
