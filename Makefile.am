SUBDIRS = src c_src

EXTRA_DIST = bootstrap

AM_ERL_FLAGS = -pa ebin

ACLOCAL_AMFLAGS = -I m4

all-local:
    test -e ebin || ln -s src ebin
    test -e priv || ln -s c_src priv

clean-local:
    -test -L ebin && $(RM) ebin
    -test -L priv && $(RM) priv

run-yaws:
	ksu root -e /bin/su yaws -c '/usr/bin/yaws -I debian_yaws -D -heart -name yaws -i'

check:
	$(MAKE) check-egssapi
	$(MAKE) check-spnego

check-spnego:
	$(ERL) $(AM_ERL_FLAGS) $(ERL_FLAGS) -s spnego test -s init stop

check-egssapi:
	$(ERL) $(AM_ERL_FLAGS) $(ERL_FLAGS) -s egssapi test -s init stop
