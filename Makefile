.PHONY: compile rel cover test typecheck doc ci

REBAR=./rebar3
SHORTSHA=`git rev-parse --short HEAD`
PKG_NAME_VER=${SHORTSHA}

OS_NAME=$(shell uname -s)

ifeq (${OS_NAME},FreeBSD)
make="gmake"
else
MAKE="make"
endif

grpc:
	REBAR_CONFIG="config/grpc_server_gen.config" $(REBAR) grpc gen && \
	REBAR_CONFIG="config/grpc_client_gen.config" $(REBAR) grpc gen

compile:
	$(REBAR) format && $(REBAR) compile

shell:
	$(REBAR) shell

clean:
	rm -rf src/autogen
	$(REBAR) clean

cover:
	$(REBAR) cover

test:
	$(REBAR) as test do eunit,ct

ci:
	$(REBAR) do dialyzer,xref && $(REBAR) as test do eunit,ct,cover
	$(REBAR) covertool generate
	codecov --required -f _build/test/covertool/sibyl.covertool.xml

typecheck:
	$(REBAR) dialyzer

doc:
	$(REBAR) edoc
