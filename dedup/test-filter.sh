#!/bin/bash

# JULEA - Flexible storage framework
# Copyright (C) 2017-2018 Michael Kuhn
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

set -e

SELF_PATH="$(readlink --canonicalize-existing -- "$0")"
SELF_DIR="${SELF_PATH%/*}"
SELF_BASE="${SELF_PATH##*/}"

. "${SELF_DIR}/../scripts/common"
. "${SELF_DIR}/../scripts/setup"
. "${SELF_DIR}/../scripts/spack"

#export G_SLICE=always-malloc
export G_SLICE=debug-blocks

set_path
set_library_path

run_test ()
{
	local build_dir

	# julea-test does not get installed, so we have to find it in the build directory.
	build_dir="$(get_directory "${SELF_DIR}/../build")"

	setup_init
	setup_start
	julea-statistics
	h5repack -v -f UD=4123,1,9 $H5_FILE_INPUT $H5_FILE_OUTPUT 
	julea-statistics
	setup_stop
}

SPACK_DIR="$(get_directory "${SELF_DIR}/..")/dependencies"

spack_load_dependencies

run_test
