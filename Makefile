# Python + Flask makefile
CC=gcc
CFLAGS=-I.

VENV = .venv
VENV_PYTHON3 = $(VENV)/bin/python3

ADMIN ?= test:testpass
PROGRAM ?= ../client

all: venv deps client

venv: $(VENV_PYTHON3)
$(VENV_PYTHON3):
	python3 -m venv "$(VENV)"

deps: venv
	$(VENV_PYTHON3) -m pip install -r requirements.txt

client: client.c requests.c helper.c buffer.c parson.c
		$(CC) -o client client.c requests.c helper.c buffer.c parson.c -Wall

A ?= --debug --admin "$(ADMIN)"
run:
	$(VENV_PYTHON3) checker.py $(PROGRAM) $(A)

clean:
	rm -f *.o client

