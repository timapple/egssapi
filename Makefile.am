REBAR=./rebar
ERL=erl

ACLOCAL_AMFLAGS = -I m4
AM_ERL_FLAGS = -pa ebin

all: src

src:
	$(REBAR) get-deps compile

clean:
	$(REBAR) clean
	rm -rf deps
	rm -rf ebin

xref: all
	$(REBAR) skip_deps=true xref

deps := $(wildcard deps/*/ebin)

dialyzer/erlang.plt:
	@mkdir -p dialyzer
	@dialyzer --build_plt --output_plt dialyzer/erlang.plt \
	-o dialyzer/erlang.log --apps kernel stdlib sasl erts syntax_tools compiler asn1 crypto; \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

dialyzer/deps.plt:
	@mkdir -p dialyzer
	@dialyzer --build_plt --output_plt dialyzer/deps.plt \
	-o dialyzer/deps.log $(deps); \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

dialyzer/egssapi.plt:
	@mkdir -p dialyzer
	@dialyzer --build_plt --output_plt dialyzer/egssapi.plt \
	-o dialyzer/egssapi.log ebin; \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

erlang_plt: dialyzer/erlang.plt
	@dialyzer --plt dialyzer/erlang.plt --check_plt -o dialyzer/erlang.log; \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

deps_plt: dialyzer/deps.plt
	@dialyzer --plt dialyzer/deps.plt --check_plt -o dialyzer/deps.log; \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

egssapi_plt: dialyzer/egssapi.plt
	@dialyzer --plt dialyzer/egssapi.plt --check_plt -o dialyzer/egssapi.log; \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

dialyzer: erlang_plt deps_plt egssapi_plt
	@dialyzer --plts dialyzer/*.plt --no_check_plt \
	--get_warnings -o dialyzer/error.log ebin; \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

check-spnego:
	$(ERL) $(AM_ERL_FLAGS) $(ERL_FLAGS) -s spnego test -s init stop

check-egssapi:
	$(ERL) $(AM_ERL_FLAGS) $(ERL_FLAGS) -s egssapi test -s init stop


.PHONY: clean src all dialyzer erlang_plt deps_plt egssapi_plt check-spnego check-egssapi
