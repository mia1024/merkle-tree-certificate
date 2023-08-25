import sys, os, pathlib

project = 'Merkle Tree Certificate'
copyright = '2023, Mia Celeste'
author = 'Mia Celeste'




extensions = ['sphinx.ext.autodoc',
              "sphinx.ext.viewcode",
              "sphinx.ext.intersphinx",
              "sphinx.ext.autosummary", ]

intersphinx_mapping = {'python': ('https://docs.python.org/3', None),
                       "cryptography": ("https://cryptography.io/en/latest", None)}
# apparently Python can't verify the certificates correctly on some Macs even after running the certificate install.
# hopefully MTC can solve this issue
tls_verify = False

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
autodoc_type_aliases = {"NodesList": "NodesList"}
autodoc_type_hints = "description"
autodoc_member_order = "bysource"
# autodoc_class_signature = "separated"
# autodoc_typehints_format = "fully-qualified"
autodoc_inherit_docstrings = False

autodoc_default_options = {
    "show-inheritance": True,
    'exclude-members': '__weakref__, __new__',
    'undoc-members': True
}

autosummary_generate = True

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']

sys.path.append(os.path.abspath(pathlib.Path(__file__).parent.parent))
