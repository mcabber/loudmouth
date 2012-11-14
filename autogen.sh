#!/bin/sh
# Run this to generate all the initial makefiles, etc.

: ${AUTORECONF=autoreconf}
: ${GTKDOCIZE=gtkdocize}

if [ "x$1" = "x-h" ] || [ "x$1" = "x--help" ]; then
	echo "./autogen.sh [-g]"
	echo
	echo " -n  disable gtk-doc"
	echo
	echo "Also uses environment variables AUTORECONF and GTKDOCIZE"
	exit 1
elif [ "x$1" = "x-n" ]; then
	# ensure, that gtk-doc.make exists and is readable
	# otherwise automake will fail - it is included from
	# doc/reference/Makefile.am
	if [ -f "./autogen.sh" ]; then
		if [ -h "./gtk-doc.make" ]; then
			rm -f "./gtk-doc.make"
		fi
		if [ -n "./gtk-doc.make" ]; then
			: > "./gtk-doc.make"
		fi
		GTKDOCIZE=":"
	else
		# Avoid creation of files in random directories
		echo "Error: You have to run this script from the root of loudmouth sources."
		exit 1
	fi
fi

$GTKDOCIZE || exit 1
$AUTORECONF --install || exit 1
