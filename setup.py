import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="securitytrailsapi",
    version="0.0.1",
    author="Dan Duffy",
    author_email="de4db1t@gmail.com",
    description="A wrapper around the SecurityTrails API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hangmansROP/securitytrailsapi",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
)