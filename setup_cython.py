"""Build Cython extensions: python setup_cython.py build_ext --inplace"""
import numpy as np
from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = [
    Extension(
        "fastpath.da_fast",
        ["fastpath/da_fast.pyx"],
        include_dirs=[np.get_include()],
    ),
    Extension(
        "fastpath.score_fast",
        ["fastpath/score_fast.pyx"],
        include_dirs=[np.get_include()],
    ),
]

setup(
    name="tenko_fastpath",
    ext_modules=cythonize(
        extensions,
        compiler_directives={"language_level": "3", "boundscheck": False},
    ),
)
