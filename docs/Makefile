# Minimal makefile for Sphinx documentation
#
ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
# You can set these variables from the command line, and also
# from the environment for the first two.
SPHINXOPTS    ?=
SPHINXBUILD   ?= $(ROOT_DIR)/.venv/bin/sphinx-build
SOURCEDIR     = source
BUILDDIR      = build

# Put it first so that "make" without argument is like "make help".
help: $(SPHINXBUILD)
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile $(SPHINXBUILD)
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

$(SPHINXBUILD):
	python3 -m venv $(ROOT_DIR)/.venv
	$(ROOT_DIR)/.venv/bin/python -m pip install $(ROOT_DIR)

distclean:
	$(RM) -rf $(ROOT_DIR)/.venv $(BUILDDIR)
