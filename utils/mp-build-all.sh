echo -e '#####################################################'
echo make -C tests/unit || exit 1
echo -e '#####################################################'
make -C tests/unit clean || exit 1
make -C tests/unit || exit 1
make -C tests/unit clean || exit 1
echo -e '################# S U C C E S S #####################\n'

OS=linux
for EPID in epid_sdk; do
	for CREDENTIALS in file hard-coded; do
		for TLS in mbedtls; do
			echo -e '#####################################################'
			echo make TARGET_OS=$OS EPID=$EPID CREDENTIALS=$CREDENTIALS TLS=$TLS
			echo -e '#####################################################'
			make TARGET_OS=$OS EPID=$EPID CREDENTIALS=$CREDENTIALS TLS=$TLS pristine || exit 1
			make TARGET_OS=$OS EPID=$EPID CREDENTIALS=$CREDENTIALS TLS=$TLS || exit 1
			make TARGET_OS=$OS EPID=$EPID CREDENTIALS=$CREDENTIALS TLS=$TLS pristine || exit 1
			echo -e '#####################################################\n'
		done
	done
done
for EPID in epid_sdk; do
	for CREDENTIALS in file hard-coded; do
		for TLS in openssl; do
			echo -e '#####################################################'
			echo make TARGET_OS=$OS EPID=$EPID CREDENTIALS=$CREDENTIALS TLS=$TLS
			echo -e '#####################################################'
			make TARGET_OS=$OS EPID=$EPID CREDENTIALS=$CREDENTIALS TLS=$TLS pristine || exit 1
			make TARGET_OS=$OS EPID=$EPID CREDENTIALS=$CREDENTIALS TLS=$TLS || exit 1
			make TARGET_OS=$OS EPID=$EPID CREDENTIALS=$CREDENTIALS TLS=$TLS pristine || exit 1
			echo -e '#####################################################\n'
		done
	done
done

echo -e '################# S U C C E S S #####################\n'
