#!/bin/sh
# The container's entrypoint: puts the status page (index.html and its copy
# of the sites' shared look, _site/) next to the status file, then runs
# beacon with the container's arguments. So the page always matches the
# image, and the web server only has to serve that folder.
#
# BEACON_STATUS_DIR   where the page goes (default /status, the folder of
#                     --status-file /status/status.json); BEACON_STATUS_DIR=
#                     (empty) leaves it alone.
set -u
dir=${BEACON_STATUS_DIR-/status}
if [ -n "$dir" ] && [ -d "$dir" ] && [ -w "$dir" ]; then
    rm -rf "$dir/_site.new" &&
        cp -R /usr/local/share/beacon/status/_site "$dir/_site.new" &&
        rm -rf "$dir/_site" && mv "$dir/_site.new" "$dir/_site" &&
        cp /usr/local/share/beacon/status/index.html "$dir/index.html.new" &&
        mv "$dir/index.html.new" "$dir/index.html" ||
        echo "beacon: the status page wasn't copied into $dir" >&2
fi
exec /usr/local/bin/beacon "$@"
