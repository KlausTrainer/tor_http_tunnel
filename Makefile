PROJECT = tor_http_tunnel

RELX:=$(shell which relx || echo ./relx)

# options

PLT_APPS = crypto asn1 public_key ssl sasl

# dependencies

DEPS = ranch cowlib
dep_ranch = git https://github.com/extend/ranch.git 1.1.0
dep_cowlib = git https://github.com/extend/cowlib.git 1.0.1

# standard targets

include erlang.mk

release: clean-release deps all
	$(RELX) -o rel -c rel/reltool.config

clean-release:
	rm -rf rel/$(PROJECT)

check test: tests

clean:: clean-release
