PROJECT = keyserver 
DIALYZER = dialyzer

REBAR := $(shell which rebar3 2>/dev/null || echo ./rebar3)
REBAR_URL := https://s3.amazonaws.com/rebar3/rebar3

all: compile

./rebar3:
	erl -noshell -s inets start -s ssl start \
        -eval '{ok, saved_to_file} = httpc:request(get, {"$(REBAR_URL)", []}, [], [{stream, "./rebar3"}])' \
        -s inets stop -s init stop
	chmod +x ./rebar3

compile: rebar3
	$(REBAR) compile

test: compile
	$(REBAR) eunit

clean: rebar3
	$(REBAR) clean

distclean: 
	rm $(REBAR)

# dializer 

build-plt:
	@$(DIALYZER) --build_plt --output_plt .$(PROJECT).plt \
		--apps kernel stdlib 

dialyze:
	@$(DIALYZER) --src src --plt .$(PROJECT).plt --no_native \
		-Werror_handling -Wrace_conditions -Wunmatched_returns -Wunderspecs

