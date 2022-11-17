:
# This package uses the GNU automake/autoconf system to help with
# portability. Automake and autoconf create a script, configure, which
# in turn creates a Makefile. So, the recommended way to get started
# with these source files is as follows:

# autoreconf runs autoconf, autoheader, aclocal, automake, autopoint,
# and libtoolize where appropriate repeatedly to remake the build
# system. Option -i installs the auxiliary files that
# automake/autoconf needs and -v makes the command verbose.
#
autoreconf -i -v || exit 1

# If autoreconf succeeded, there should now be a script called
# configure. It accepts various options, e.g., to set the directory
# where to install the finished program later, but we'll just run it
# with the default options. You can always re-run it later.

./configure || exit 1

# If all is well, we have a Makefile now...

echo
echo "Build system created. Next, run \"make\" to compile the program."

